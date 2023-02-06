// An object of options to indicate where to post to
const http = require('http');
const querystring = require('querystring');

//simple form data devloped by Pakainfo.com
var parameters = querystring.stringify({
    service: "turn",
    username: "user-1"
});

//simple request_datauest option devloped by Pakainfo.com
var options = {
    host: '10.104.81.51',
    port: 8080,
    method: 'GET',
    path: '/ice?'+parameters,
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': parameters.length
    }
};


//simple request_datauest object devloped by Pakainfo.com
var request_data = http.request(options, function (res) {
    var response = '';
    res.on('data', function (chunk) {
        response += chunk;
    });
    res.on('end', function () {
        console.log(response);
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