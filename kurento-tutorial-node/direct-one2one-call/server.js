/*
 * (C) Copyright 2014 Kurento (http://kurento.org/)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

var path = require('path');
var express = require('express');
var ws = require('ws');
var minimist = require('minimist');
var url = require('url');
var kurento = require('kurento-client');
var fs    = require('fs');
var https = require('https');
var http = require('http');

const auth = require('@l7mp/stunner-auth-lib');

var argv = minimist(process.argv.slice(2), {
  default: {
    as_uri: "https://localhost:8443/",
  }
});

var options =
    {
      key:  fs.readFileSync('keys/server.key'),
      cert: fs.readFileSync('keys/server.crt')
    };

var app = express();

/*
 * Definition of global variables.
 */

var userRegistry = new UserRegistry();
var candidatesQueue = {};
var idCounter = 0;

function nextUniqueId() {
  idCounter++;
  return idCounter.toString();
}

/*
 * Definition of helper classes
 */

// Represents caller and callee sessions
function UserSession(id, name, ws) {
  this.id = id;
  this.name = name;
  this.ws = ws;
  this.peer = null;
  this.sdpOffer = null;
}

UserSession.prototype.sendMessage = function(message) {
  this.ws.send(JSON.stringify(message));
}

// Represents registrar of users
function UserRegistry() {
  this.usersById = {};
  this.usersByName = {};
}

UserRegistry.prototype.register = function(user) {
  this.usersById[user.id] = user;
  this.usersByName[user.name] = user;
}

UserRegistry.prototype.unregister = function(id) {
  var user = this.getById(id);
  if (user) delete this.usersById[id]
  if (user && this.getByName(user.name)) delete this.usersByName[user.name];
}

UserRegistry.prototype.getById = function(id) {
  return this.usersById[id];
}

UserRegistry.prototype.getByName = function(name) {
  return this.usersByName[name];
}

UserRegistry.prototype.removeById = function(id) {
  var userSession = this.usersById[id];
  if (!userSession) return;
  delete this.usersById[id];
  delete this.usersByName[userSession.name];
}

/*
 * Server startup
 */

var asUrl = url.parse(argv.as_uri);
var port = asUrl.port;
var server = https.createServer(options, app).listen(port, function() {
    console.log('STUNnerTutorial started: Kurento direct call');
  console.log('Open ' + url.format(asUrl) + ' with a WebRTC capable browser');
});

var wss = new ws.Server({
  server : server,
  path : '/one2one'
});

wss.on('connection', function(ws) {
  var sessionId = nextUniqueId();
  console.log('Connection received with sessionId ' + sessionId);

  ws.on('error', function(error) {
    console.log('Connection ' + sessionId + ' error');
    stop(sessionId);
  });

  ws.on('close', function() {
    console.log('Connection ' + sessionId + ' closed');
    stop(sessionId);
    userRegistry.unregister(sessionId);
  });

  ws.on('message', function(_message) {
    var message = JSON.parse(_message);
    console.log('Connection ' + sessionId + ' received message ', message);

    switch (message.id) {
    case 'register':
      register(sessionId, message.name, ws);
      break;

    case 'call':
      call(sessionId, message.to, message.from, message.sdpOffer);
      break;

    case 'incomingCallResponse':
      incomingCallResponse(sessionId, message.from, message.callResponse, message.sdpAnswer, ws);
      break;

    // case 'callAck':
    //   callAck(sessionId, message.response, ws);
    //   break;

    case 'stop':
      stop(sessionId);
      break;

    case 'onIceCandidate':
      onIceCandidate(sessionId, message.candidate);
      break;

    default:
      ws.send(JSON.stringify({
        id : 'error',
        message : 'Invalid message ' + message
      }));
      break;
    }

  });
});

function stop(sessionId) {
  var stopperUser = userRegistry.getById(sessionId);
  if(stopperUser && stopperUser.peer){
    var stoppedUser = userRegistry.getByName(stopperUser.peer);
    stopperUser.peer = null;

    if (stoppedUser) {
      stoppedUser.peer = null;
      var message = {
        id: 'stopCommunication',
        message: 'remote user hanged out'
      };
      stoppedUser.sendMessage(message);
    }
    clearCandidatesQueue(sessionId);
  }
}

function incomingCallResponse(calleeId, from, callResponse, calleeSdpAnswer, ws) {

  clearCandidatesQueue(calleeId);

  function onError(callerReason, calleeReason) {
    if (caller) {
      var callerMessage = {
        id: 'callResponse',
        response: 'rejected'
      }
      if (callerReason) callerMessage.message = callerReason;
      caller.sendMessage(callerMessage);
    }

    var calleeMessage = {
      id: 'stopCommunication'
    };
    if (calleeReason) calleeMessage.message = calleeReason;
    callee.sendMessage(calleeMessage);
  }

  var callee = userRegistry.getById(calleeId);
  if (!from || !userRegistry.getByName(from)) {
    return onError(null, 'unknown from = ' + from);
  }
  var caller = userRegistry.getByName(from);
  
  if (callResponse === 'accept') {
    var accept = {
      id: 'callResponse',
      response: 'accepted',
      sdpAnswer: calleeSdpAnswer
    };
    caller.sendMessage(accept);
    
  } else {
    var decline = {
      id: 'callResponse',
      response: 'rejected',
      message: 'user declined'
    };
    caller.sendMessage(decline);
  }
}

function call(callerId, to, from, sdpOffer) {
  clearCandidatesQueue(callerId);

  var caller = userRegistry.getById(callerId);
  var rejectCause = 'User ' + to + ' is not registered';
  if (userRegistry.getByName(to)) {
    var callee = userRegistry.getByName(to);
    caller.sdpOffer = sdpOffer
    callee.peer = from;
    caller.peer = to;
    var message = {
      id: 'incomingCall',
      from: from,
      sdpOffer: sdpOffer,
    };
    try{
      return callee.sendMessage(message);
    } catch(exception) {
      rejectCause = "Error " + exception;
    }
  }
  var message  = {
    id: 'callResponse',
    response: 'rejected: ',
    message: rejectCause
  };
  caller.sendMessage(message);
}

// function callAck(callerId, response, ws){
//   var caller = userRegistry.getById(callerId);
//   if (caller) {
//     var callee = userRegistry.getByName(caller.peer);
//     if(callee){
//       var message = {
//         id: 'startCommunication',
//       };
//       callee.sendMessage(message);
//     } else {
//       var message = {
//         id: 'stopCommunication',
//         message: 'remote user rejected',
//       };
//       calleee.sendMessage(message);
//     }
//   } else {
//     console.log("callAck from unknown user");
//   }
// }
const querystring = require('querystring');

function generateIceConfig(ws, name) {
// An object of options to indicate where to post to

//simple form data devloped by Pakainfo.com
  var parameters = querystring.stringify({
    service: "turn",
    username: name,
    icetransportpolicy: "relay"
    // konfigbol szedje ki hogy mi a username
  });

//simple request_datauest option devloped by Pakainfo.com
  var options = {
    host: 'authrest.stunner.svc.cluster.local', //stunner-auth
    port: 8080,
    method: 'GET',
    path: '/ice?'+parameters,
  };

  var iceConfiguration = '';
//simple request_datauest object devloped by Pakainfo.com
  var request_data = http.request(options, function (res) {
    var response = '';
    res.on('data', function (chunk) {
      response += chunk;
      console.log('on data response'+ response)

    });
    res.on('end', function () {
      iceConfiguration += response;
      console.log('end response'+ iceConfiguration)
      console.log("Generated ICE config:" + iceConfiguration);
      ws.send(JSON.stringify({id: 'registerResponse', response: 'accepted', iceConfiguration: iceConfiguration}));

    });
    res.on('error', function (err) {
      console.log(err);
    })
  });
//simple request_data error devloped by Pakainfo.com
  request_data.on('error', function (err) {
    console.log(err);
  });

//simple send request_datauest witht This parameters form devloped by Pakainfo.com
  request_data.write(parameters);
  request_data.end();
}

function register(id, name, ws, callback) {
  function onError(error) {
    ws.send(JSON.stringify({id:'registerResponse', response : 'rejected ', message: error}));
  }

  if (!name) {
    return onError("empty user name");
  }

  if (userRegistry.getByName(name)) {
    return onError("User " + name + " is already registered");
  }

  userRegistry.register(new UserSession(id, name, ws));
  try {
    generateIceConfig(ws, name);
  } catch(exception) {
    onError(exception);
  }
}

function clearCandidatesQueue(sessionId) {
  if (candidatesQueue[sessionId]) {
    delete candidatesQueue[sessionId];
  }
}

function onIceCandidate(sessionId, _candidate) {
  var candidate = kurento.getComplexType('IceCandidate')(_candidate);

  user = userRegistry.getById(sessionId);
  if(user){
    peer = userRegistry.getByName(user.peer);
    if(peer){
      // first, send the cached candidates
      flushCandidatesQueue(sessionId, peer);
      sendCandidate(peer, candidate);
    } else {
      // no peer yet, cache candidate
      if (!candidatesQueue[sessionId]) {
        candidatesQueue[sessionId] = [];
      }
      candidatesQueue[sessionId].push(candidate);
    }
  }
}

function flushCandidatesQueue(sessionId, peer){
  if (candidatesQueue[sessionId]) {
    while(candidatesQueue[sessionId].length) {
      var candidate = candidatesQueue[sessionId].shift();
      sendCandidate(peer, candidate);
    }
  }
}

function sendCandidate(peer, candidate){
  peer.ws.send(JSON.stringify({
    id : 'iceCandidate',
    candidate : candidate
  }));
}
    
app.use(express.static(path.join(__dirname, 'static')));

// Local Variables:
// js-indent-level: 2
// indent-tabs-mode: nil
// End:
