const querystring = require('querystring');


const parameters ={
    service: "turn",
    username: "user-1"
};



const post_data = querystring.stringify(parameters);



const options = {
    url: "http://authrest.stunner.svc.cluster.local",
    port: "8080",
    path: "/ice",
    method: "GET",
    headers : {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
}



// We need this to build our post string
var querystring = require('querystring');
var http = require('http');
var fs = require('fs');

function PostCode(codestring) {
    // Build the post string from an object
    var post_data = querystring.stringify({
        'service' : 'turn',
        'username': 'user-1'
    });

    // An object of options to indicate where to post to
    var post_options = {
        host: 'http://authrest.stunner.svc.cluster.local',
        port: '8080',
        path: '/ice',
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(post_data)
        }
    };

    // Set up the request
    var post_req = http.request(post_options, function(res) {
        res.setEncoding('utf8');
        res.on('data', function (chunk) {
            console.log('Response: ' + chunk);
        });
    });

    // post the data
    post_req.write(post_data);
    post_req.end();

}

// This is an async file read
fs.readFile('LinkedList.js', 'utf-8', function (err, data) {
    if (err) {
        // If this were just a small part of the application, you would
        // want to handle this differently, maybe throwing an exception
        // for the caller to handle. Since the file is absolutely essential
        // to the program's functionality, we're going to exit with a fatal
        // error instead.
        console.log("FATAL An error occurred trying to read in the file: " + err);
        process.exit(-2);
    }
    // Make sure there's data before we post it
    if(data) {
        PostCode(data);
    }
    else {
        console.log("No data to post");
        process.exit(-1);
    }
});










const axios = require('axios')



axios
    .post('http://authrest.stunner.svc.cluster.local/ice?', post_data)
    .then(res => {
        console.log(`Status: ${res.status}`)
        console.log('Bodjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjy: ', res.data)
    })
    .catch(err => {
        console.error(err)
    })


/app # cat ok.js

var https = require('https');

const http = require('http');
http.get('http://authrest.stunner.svc.cluster.local:8080/ice?service=turn&username=user-1', (resp) => {
    let data = '';
    // A chunk of data has been received.
    resp.on('data', (chunk) => {
        data += chunk;

    });
    // The whole response has been received. Print out the result.
    resp.on('end', () => {
        console.log(JSON.parse(data).explanation);
    });
}).on("error", (err) => {
    console.log("Error: " + err.message);
});
