const WebSocketServer = require('websocket').server;
const randomstring = require("randomstring");
const { v4: uuidv4 } = require('uuid');
const openpgp = require('openpgp');
const bcrypt = require ('bcrypt');
const http = require('http');
const fs = require('fs');

function guidGenerator() {
    var S4 = function() {
       return (((1+Math.random())*0x10000)|0).toString(16).substring(1);
    };
    return (S4()+S4()+S4()+S4()+"-"+S4()+S4()+S4()+S4()+"-"+S4()+S4()+S4()+S4()+"-"+S4()+S4()+S4()+S4()+"-"+S4()+S4()+S4()+S4());
}

var globalPrv = '';
var globalPub = '';
var globalRev = '';
var clients = {};
const saltRounds = 12;
var passphrase = uuidv4() + "SECRET" + uuidv4() + uuidv4() + guidGenerator() + guidGenerator() + guidGenerator() + "SECRET" + guidGenerator() + guidGenerator() + "VERYPOG" + guidGenerator() + guidGenerator();
var sessionTokens = {};

const geneid = () => {
    return randomstring.generate({
        length: 16,
        charset: 'alphabetic'
    });
};

function genPasswordHash(password) {
    bcrypt.hash(password, saltRounds, function(err, hash) {
        console.log(hash);
    });
}

var server = http.createServer(function(request, response) {
    console.log((new Date()) + ' Received request for ' + request.url);
    var script = fs.readFileSync('website/index.js', 'utf8');
    var openpgpScript = fs.readFileSync('website/openpgp.js', 'utf8');
    request.url = decodeURIComponent(request.url);
    response.write(`
    <!DOCTYPE html>
    <html>
        <head>
            <title>VSM - ${request.url.split('/')[1]}</title>

            <script>${openpgpScript}</script>

            <script>
                if (${request.url === '/'}) {
                    location = '/Room 1';
                }
            </script>

            <style>
                html,
                body {
                    margin: 0;
                    height: 100%;
                    width: 100%;
                    overflow: hidden;
                    font-family: 'Roboto', sans-serif;
                }

                .message {
                    color: #fff;
                    padding-bottom: 10px;
                }

                #ROOMNAME {
                    padding-left: 20px;
                }

                #MESSAGESHOLDER {
                    width: 100%;
                    height: 90%;
                    background-color: #0a0a0a;
                    list-style-type: none;
                    margin-left: -25px;
                    padding-top: 10px;
                    overflow: auto;
                }

                #MESSAGEINPUT {
                    width: 100%;
                    height: 60px;
                    position: absolute;
                    bottom: 0;
                    background-color: #5a5a5a;
                }

                #MESSAGEINPUTBOX {
                    background: transparent;
                    color: #fff;
                    border: none;
                    height: 100%;
                    width: 96.8%;
                    outline: none;
                    font-size: 20px;
                    padding-left: 20px;
                }
            </style>
        </head>
        <body>
            <h1 id="ROOMNAME">${request.url.split('/')[1]}</h1>
            <div style="height: 100%; width: 100%;">
                <ul id="MESSAGESHOLDER">

                </ul>
                <div id="MESSAGEINPUT">
                    <input type="text" id="MESSAGEINPUTBOX" placeholder="Type a message...">
                </div>
            </div>
            <script>
                var messageHolder = document.getElementById("MESSAGESHOLDER");
                var messageInputField = document.getElementById("MESSAGEINPUTBOX");
                var currentRoomID = "CURRENTROOMID";
            
                ${script}
            </script>
        </body>
    </html>
    `
    .split('ROOMNAME').join(geneid())
    .split('MESSAGESHOLDER').join(geneid())
    .split('MESSAGEINPUT').join(geneid())
    .split('MESSAGEINPUTBOX').join(geneid())
    .split('CURRENTROOMID').join(request.url.split('/')[1])
    .split('                    ').join('')
    .split('                ').join('')
    , 'utf8');

    response.end();
});

console.log("Generating new PGP keypair")
openpgp.generateKey({
    type: 'ecc',
    curve: 'curve25519',
    userIDs: [{ name: 'Anonymous', email: 'anon@anonymous.com' }],
    passphrase: passphrase,
    format: 'armored'
}).then(d => {
    var { privateKey, publicKey, revocationCertificate } = d;
    console.log("Keypair generated")
    globalPrv = privateKey;
    globalPub = publicKey;
    globalRev = revocationCertificate;
    server.listen(80, function() {
        console.log((new Date()) + ' Server is listening on port 80');
    });
});

wsServer = new WebSocketServer({
    httpServer: server,
    autoAcceptConnections: false
});

function originIsAllowed(origin) {
  return true;
}

wsServer.on('request', function(request) {
    if (!originIsAllowed(request.origin)) {
      request.reject();
      console.log((new Date()) + ' Connection from origin ' + request.origin + ' rejected.');
      return;
    }
    
    var CID = '';
    var shakeInitDone = false;
    var connection = request.accept();
    function send(json, tconnection, pub) {
        clientid = CID;
        if (tconnection == undefined) {
            tconnection = clients[clientid].connection
        }
        var lastState = uuidv4();
        try { clients[clientid].lastState = lastState; } catch { }
        json.state = lastState;
        console.log("Sending data to client")
        if (clients[clientid].publicKey && shakeInitDone) {
            if (pub == undefined) {
                pub = clients[clientid].publicKey
            }
            openpgp.createMessage({ text: JSON.stringify(json) })
            .then(msg => {
                openpgp.readPrivateKey({ armoredKey: globalPrv }).then(pk => {
                    openpgp.decryptKey({
                        privateKey: pk,
                        passphrase
                    }).then(privateKey => {
                        openpgp.readKey({ armoredKey: pub }).then(publicKey => {
                            openpgp.encrypt({
                                message: msg,
                                encryptionKeys: publicKey,
                                signingKeys: privateKey
                            }).then(r => {
                                var json = {
                                    type: 'encrypted-data',
                                    data: r
                                }
                                tconnection.sendUTF(JSON.stringify(json));
                            });
                        });
                    });
                });
            })
        } else {
            tconnection = connection
            tconnection.sendUTF(JSON.stringify(json));
        }
    }
    console.log((new Date()) + ' Connection accepted.');
    
    connection.on('message', function(message) {
        if (message.type === 'utf8') {
            try {
                var data = JSON.parse(message.utf8Data);
            } catch { }
            function showResponse() {
                try {
                    console.log('Received Message: ' + JSON.stringify(JSON.parse(message.utf8Data)));
                } catch {
                    console.log('Received Encrypted Message: ' + message.utf8Data);
                }
            }
            //showResponse()
            if (shakeInitDone) {
                try {
                    openpgp.readPrivateKey({ armoredKey: globalPrv }).then(pk => {
                        openpgp.decryptKey({
                            privateKey: pk,
                            passphrase
                        }).then(privateKey => {
                            openpgp.readKey({ armoredKey: clients[CID].publicKey }).then(publicKey => {
                                openpgp.readMessage({
                                    armoredMessage: message.utf8Data
                                }).then(msg => {
                                    openpgp.decrypt({
                                        message: msg,
                                        decryptionKeys: privateKey,
                                        expectSigned: true,
                                        verificationKeys: publicKey,
                                    }).then(d => {
                                        var { data: decrypted, signatures } = d;
                                        if (signatures.length > 0) {
                                            data = JSON.parse(decrypted);
                                            process();
                                        } else {
                                            console.log("Data was not signed, ignoring")
                                        }
                                    }).catch(e => {
                                        console.log("Data was not signed, ignoring")
                                    });
                                });
                            });
                        });
                    });
                } catch (e) {
                    console.log("Error decrypting data")
                    console.log(e.stack)
                    send({
                        type: 'error',
                        code: 'decrypt-error',
                        data: 'Error decrypting data, please try again'
                    });

                }
            } else {
                process()
            }
            function process() {
                if (data.type === 'handshake-init' && !shakeInitDone) {
                    var clientID = uuidv4();
                    CID = clientID;
                    clients[clientID] = {
                        connection: connection,
                        encryptionType: data.encryption,
                        publicKey: data.encryption.public
                    }
                    send({
                        type: 'handshake-ack',
                        encryption: {
                            type: 'pgp dual',
                            public: globalPub
                        },
                        clientID: clientID
                    });
                    shakeInitDone = true;
                } else if (data.type === 'handshake-com' && shakeInitDone) {
                    send({
                        type: 'command',
                        command: 'startRegister'
                    });
                } else if (data.type === 'authenticate' && shakeInitDone) {
                    try {
                        var username = data.username;
                        var password = data.password;
                        var foundLogin = false;

                        var users = JSON.parse(fs.readFileSync('users.db', 'utf8'));
                        for (i=0; i<Object.keys(users).length; i++) {
                            var key = Object.keys(users)[i];

                            if (users[key].user.displayName === username) {
                                foundLogin = true;
                                bcrypt.compare(password, users[key].password.hash, function(err, result) {
                                    if (result) {
                                        var session = uuidv4() + "-" + guidGenerator();
                                        sessionTokens[session] = {
                                            clientID: CID,
                                            userID: key,
                                            start: new Date().getTime().toString(),
                                            displayName: users[key].user.displayName
                                        }
                                        send({
                                            type: 'authenticate',
                                            success: true,
                                            user: users[key].user.displayName,
                                            sessionID: session
                                        });
                                    } else {
                                        send({
                                            type: 'authenticate',
                                            success: false,
                                            code: 'invalid-username-or-password',
                                            error: 'Invalid username or password'
                                        })
                                    }
                                });
                                break;
                            }
                        }
                        if (!foundLogin) {
                            send({
                                type: 'authenticate',
                                success: false,
                                code: 'invalid-username-or-password',
                                error: 'Invalid username or password'
                            })
                        }
                    } catch {
                        send({
                            type: 'error',
                            code: 'auth-error',
                            error: 'Error authenticating, please try again'
                        })
                    }
                } else if (data.type === 'join-room' && shakeInitDone) {
                    if (data.sessionID != undefined && data.roomID != undefined) {
                        sessionTokens[data.sessionID].room = data.roomID;
                        send({
                            type: 'join-room',
                            success: true,
                            room: data.roomID
                        });
                        for (i=0; i<Object.keys(sessionTokens).length; i++) {
                            var k = Object.keys(sessionTokens)[i];
                            if (sessionTokens[k].room === sessionTokens[data.sessionID].room) {
                                send({
                                    type: 'user-message',
                                    content: sessionTokens[data.sessionID].displayName + " has joined the room",
                                    user: "SYSTEM"
                                }, clients[sessionTokens[k].clientID].connection, clients[sessionTokens[k].clientID].publicKey);
                            }
                        }
                    }
                } else if (data.type === 'message-send' && shakeInitDone) {
                    for (i=0; i<Object.keys(sessionTokens).length; i++) {
                        var k = Object.keys(sessionTokens)[i];
                        if (sessionTokens[k].room === sessionTokens[data.sessionID].room) {
                            send({
                                type: 'user-message',
                                content: data.message,
                                user: sessionTokens[data.sessionID].displayName
                            }, clients[sessionTokens[k].clientID].connection, clients[sessionTokens[k].clientID].publicKey);
                        }
                    }
                } else if (data.type === 'me' && shakeInitDone) {
                    if (data.sessionID != undefined) {
                        if (Object.keys(sessionTokens).includes(data.sessionID)) {
                            send({
                                type: 'authenticate',
                                success: true,
                                user: sessionTokens[data.sessionID].displayName,
                                sessionID: data.sessionID
                            });
                        } else {
                            send({
                                type: 'me',
                                invalid: true
                            });
                        }
                    }
                }
            }
        }
        else if (message.type === 'binary') {
            console.log('Received Binary Message of ' + message.binaryData.length + ' bytes');
            connection.sendBytes(message.binaryData);
        }
    });
    connection.on('close', function(reasonCode, description) {
        console.log((new Date()) + ' Peer ' + connection.remoteAddress + ' disconnected.');
    });
});