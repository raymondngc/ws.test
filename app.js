var express = require('express');
var path = require('path');
var Bunyan = require('bunyan');
var logger = Bunyan.createLogger({
    name: 'ws.server',
    streams: [{
        level: Bunyan.DEBUG,
        path: './log.log'
    }]
});

var fs = require('fs');
var https = require('https');
var cookie = require('cookie');
var bodyParser = require('body-parser');
var _ = require('lodash');


var WebSocketServer = require('ws').Server,
    wss = new WebSocketServer({
        port: 8181,
        verifyClient: function(info, callback) {
            //            if (info.secure !== true) {
            //                callback(false);
            //                return;
            //            }
            var parsed_cookie = cookie.parse(info.req.headers['cookie']);

            if ('user' in parsed_cookie) {
                console.log('wss connection verifyClient got user ' + parsed_cookie['user']);
                // may verify client connection here.
                //                if (checkAuth(parsed_cookie['credentials'])) {
                callback(true);
                return;
                //                }
            }
            callback(false);
        }
    });

var wsList = {};

function sendMessage(msg, userIDSend) {
    if (msg.hasOwnProperty('toUser')) {
        console.log('user is ', msg.toUser);
        if (!(_.isNil(wsList[msg.toUser]))) {
            console.log("sending message to " + msg.toUser);
            var msgSend = {};
            msgSend.fromUser = userIDSend;
            msgSend.message = msg.message
            wsList[msg.toUser].send(JSON.stringify(msgSend));
        }
    }
}

wss.on('connection', function(ws) {
    console.log('wss client connected');
    var parsed_cookie = cookie.parse(ws.upgradeReq.headers.cookie);

    var userID = parsed_cookie['user'];
    console.log('wss connection onConnect got user ' + parsed_cookie['user']);
    wsList[userID] = ws;

    ws.on('message', function(msgStr) {
        console.log('msg %j', msgStr);
        var msg = JSON.parse(msgStr);
        var userIDSend = _.findKey(wsList, ws);

        sendMessage(msg, userIDSend)
    });

    ws.onclose = function(e) {
        console.log("Connection closed");
        var userIDClose = _.findKey(wsList, ws);
        if (!(_.isNil(userIDClose)))
            delete wsList[userIDClose];
    }
});




var app = express();
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json()); // for parsing application/json
app.use(bodyParser.urlencoded({
    extended: true
}));

app.get('/login', function(req, res) {
    fs.readFile('./public/login.html', function(err, html) {
        if (err) {
            throw err;
        }
        res.writeHeader(200, {
            "Content-Type": "text/html"
        });
        res.write(html);
        res.end();
    });
});

app.post("/login", function(req, res) {
    if (req.body !== 'undefined') {
        console.log('req body %j', req.body);
        res.cookie('user', req.body['username']);
        res.redirect('/secured');
        return;
    }
    res.sendStatus(401);
});

app.get('/secured', function(req, res) {
    cookies = cookie.parse(req.headers['cookie']);
    if (!cookies.hasOwnProperty('user')) {
        console.log('access /secure without user cookie!');
        res.redirect('/login');
    } else {
        fs.readFile('./secured.html', function(err, html) {
            if (err) {
                throw err;
            }
            res.writeHeader(200, {
                "Content-Type": "text/html"
            });
            res.write(html);
            res.end();
        });
    }
});



// Restful API
app.post('/sendMessage', function(req, res) {
    console.log("sendMessage Post request received ....");
    console.log("sendMessage req  %j ", req.body);
    console.log("sendMessage from user: " + req.body.fromUser);
    sendMessage(req.body, req.body.fromUser)
});




app.set('port', process.env.PORT || 3000);
var server = app.listen(app.get('port'), function() {
    logger.debug('Express server listening on port ' + server.address().port);
});