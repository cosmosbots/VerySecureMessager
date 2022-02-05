function guidGenerator() {
    var S4 = function() {
       return (((1+Math.random())*0x10000)|0).toString(16).substring(1);
    };
    return (S4()+S4()+S4()+S4()+"-"+S4()+S4()+S4()+S4()+"-"+S4()+S4()+S4()+S4()+"-"+S4()+S4()+S4()+S4()+"-"+S4()+S4()+S4()+S4());
}

const passphrase = guidGenerator() + guidGenerator() + guidGenerator() + "SECRET" + guidGenerator() + guidGenerator() + "VERYPOG" + guidGenerator() + guidGenerator();

console.log("Generating new PGP keypair")
openpgp.generateKey({
    type: 'ecc',
    curve: 'curve25519',
    userIDs: [{ name: 'Anonymous', email: 'anon@anonymous.com' }],
    passphrase: passphrase,
    format: 'armored'
}).then(d => {
    const { privateKey, publicKey, revocationCertificate } = d;
    console.log("Keypair generated")
    online(privateKey, publicKey, revocationCertificate);
});

function codeTamperReaction(reason) {
    console.clear();
    if (reason == 'SECURE_SERVERCONNECTED_FLAG_TP') {
        console.log("Blocked access to SECURE_SERVERCONNECTED_FLAG_TP, code may be tampered with")
    }
    console.log("Refreshing page due to detected security issue")
    setTimeout(() => {
        location.reload();
    }, 1000);
}

var SECURE_SERVERCONNECTED_FLAG_TP_ACCESS = false;

var SECURE_SERVERCONNECTED_FLAG_TP = new Proxy({active: false}, {
    set: function (target, key, value) {
        if (value) {
            target[key] = value;
        }
        if (value != true) {
            setTimeout(() => { codeTamperReaction('SECURE_SERVERCONNECTED_FLAG_TP') });
            return true;
        }
        return true;
    },
    get: function (target, key) {
        if (SECURE_SERVERCONNECTED_FLAG_TP_ACCESS) {
            SECURE_SERVERCONNECTED_FLAG_TP_ACCESS = false;
            return target[key];
        } else {
            setTimeout(() => { codeTamperReaction('SECURE_SERVERCONNECTED_FLAG_TP') });
            return undefined;
        }
    }
});

function wrap( str ) {
    return '<a href="' + str + '">' + str + '<\/a>';
};

document.body.scrollTop = document.documentElement.scrollTop = 0;

setInterval(() => {
    document.body.scrollTop = document.documentElement.scrollTop = 0;
}, 250);

function online(privateKey, publicKey, revocationCertificate) {
    SECURE_SERVERCONNECTED_FLAG_TP_ACCESS = true;
    if (SECURE_SERVERCONNECTED_FLAG_TP.active) {
        return;
    } else {
        SECURE_SERVERCONNECTED_FLAG_TP.active = true;
    }
    if (typeof SECURE_SERVERCONNECTED_FLAG_TP != 'object') {
        codeTamperReaction('SECURE_SERVERCONNECTED_FLAG_TP');
        return;
    }

    console.log("Starting WebSockets connection")
    const connection = new WebSocket('wss://' + location.host)
    console.log("Waiting for connection")

    var serverPub = '';
    var state = '';
    var clientID = '';
    var useEncryption = false;
    var userData = {}

    function send(json, spinner = true) {
        console.log("Sending data to server")
        if (!Object.keys(json).includes('state')) {
            json.state = state;
        }
        if (useEncryption) {
            openpgp.createMessage({ text: JSON.stringify(json) })
            .then(msg => {
                openpgp.readPrivateKey({ armoredKey: privateKey }).then(pk => {
                    openpgp.decryptKey({
                        privateKey: pk,
                        passphrase
                    }).then(privateKey => {
                        openpgp.readKey({ armoredKey: serverPub }).then(publicKey => {
                            openpgp.encrypt({
                                message: msg,
                                encryptionKeys: publicKey,
                                signingKeys: privateKey
                            }).then(r => {
                                connection.send(r);
                                showSpinner();
                            });
                        });
                    });
                });
            })
        } else {
            connection.send(JSON.stringify(json));
        }
    }

    var lastMsg = 0;

    function main() {
        console.log("Connection ready")
        console.log("Sending encryption handshake")
        send({
            type: 'handshake-init',
            encryption: {
                type: 'pgp dual',
                public: publicKey
            }
        });
    }

    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
    }

    function authUser(username, password) {
        console.log("Authenticating user")
        send({
            type: 'authenticate',
            username: username,
            password: password
        });
    }

    function showLoginCover() {
        loginCover.style.display = 'block';
        loginCover.style.opacity = 1;
    }

    function hideLoginCover() {
        loginCover.style.opacity = 0;
        setTimeout(() => {
            loginCover.style.display = 'none';
        }, 300);
    }

    function promptAuth() {
        showLoginCover();
        loginBtn.innerText = 'Login';
        console.log("Listening for login button click")
        loginBtn.onclick = () => {
            loginBtn.disabled = true;
            loginBtn.innerText = '...';
            authUser(loginField.value, passField.value);
        };
        //authUser(prompt('Please Log in. Username:',' '), prompt('Please Log in. Password:',' '));
    }

    function addMessage(message, dn, msgid, type) {
        var opacity = "1";
        if (type == 'inProgress') {
            opacity = "0.5";
        } else if (type == 'confirmed') {
            opacity = "1";
        }
        var newMsgObj = document.createElement('li');
        var msgBlockTop = `
        <span style="font-weight:bold;" class="NameHeader">${dn}</span>
        <br>
        `
        try {
            if (!messageHolder.lastElementChild.className.includes('message-inprogress')) {
                if (messageHolder.lastElementChild.getElementsByClassName('NameHeaderVal')[0].innerText == dn) {
                    msgBlockTop = '';
                    newMsgObj.classList.add('message-lonely');
                    if (messageHolder.lastElementChild.className == "message") {
                        messageHolder.lastElementChild.style.paddingBottom = "1px";
                    }
                } else {
                    if (messageHolder.lastElementChild.className.includes('message-lonely')) {
                        messageHolder.lastElementChild.classList.remove('message-lonely');
                        messageHolder.lastElementChild.style.paddingBottom = "10px";
                    }
                }
            }
        } catch { }
        if (type == 'inProgress') {
            newMsgObj.classList.add('message-inprogress');
        }
        newMsgObj.innerHTML = `
        ${msgBlockTop}
        <span style="display:none;" class="NameHeaderVal">${dn}</span>
        <span style="color:silver;opacity:${opacity}">${message.replace(/\bhttp[^ ]+/ig, wrap)}</span>
        `;
        newMsgObj.classList.add('message');
        newMsgObj.id = msgid;
        messageHolder.appendChild(newMsgObj);
    }

    function showSpinner() {
        cornerSpinner.style.opacity = 1;
    }

    function hideSpinner() {
        cornerSpinner.style.opacity = 0;
    }

    connection.onopen = main;

    connection.onclose = function(e) {
        addMessage('Lost connection to server', 'SYSTEM', '0', 'confirmed');
        console.log("Connection closed");
    }

    connection.onmessage = function(message) {
        showSpinner();
        if (message.isTrusted) {
            var data = JSON.parse(message.data);
            console.log('Received Message: ' + JSON.stringify(data));
            if (data.type === 'handshake-ack') {
                console.log("Received handshake-ack")
                console.log("Encryption handshake complete")
                console.log("Server will now encrypt outgoing data")
                useEncryption = true;
                serverPub = data.encryption.public;
                state = data.state;
                clientID = data.clientID;
                hideSpinner();
                send({
                    type: 'handshake-com',
                    state: state
                });
            } else if (data.type === 'encrypted-data') {
                console.log("Message is encrypted, attempting to decrypt")
                openpgp.readPrivateKey({ armoredKey: privateKey }).then(pk => {
                    openpgp.decryptKey({
                        privateKey: pk,
                        passphrase
                    }).then(privateKey => {
                        openpgp.readKey({ armoredKey: serverPub }).then(serverPub => {
                            openpgp.readMessage({
                                armoredMessage: data.data
                            }).then(msg => {
                                openpgp.decrypt({
                                    message: msg,
                                    decryptionKeys: privateKey,
                                    expectSigned: true,
                                    verificationKeys: serverPub,
                                }).then(d => {
                                    var { data: decrypted, signatures } = d;
                                    if (signatures.length > 0) {
                                        hideSpinner();

                                        var data = JSON.parse(decrypted);
                                        state = data.state;

                                        console.log("Message decrypted successfully")

                                        function showResponse() {
                                            console.log(data)
                                        }

                                        showResponse();

                                        if (data.type === 'command') {
                                            if (data.command === 'startRegister') {
                                                console.log("Encryption succeeded");
                                                if (getCookie('sesh') != undefined && getCookie('sesh') != '') {
                                                    loginField.value = getCookie('sesh');
                                                }
                                                promptAuth();
                                            }
                                        } else if (data.type === 'me') {
                                            if (data.invalid) {
                                                promptAuth();
                                            }
                                        } else if (data.type === 'authenticate') {
                                            if (data.success) {
                                                console.log('authData', data)
                                                console.log("Login success")
                                                document.cookie = "sesh=" + data.user;
                                                userData.displayName = data.user
                                                userData.sessionID = data.sessionID
                                                send({
                                                    type: 'join-room',
                                                    roomID: currentRoomID,
                                                    sessionID: userData.sessionID
                                                });
                                            } else {
                                                document.cookie = "sesh="
                                                console.error("Login failed:\n" + data.error);
                                                loginBtn.disabled = false;
                                                loginBtn.innerText = 'Login';
                                                promptAuth();
                                            }
                                        } else if (data.type === 'user-message') {
                                            console.log("Received user message")
                                            addMessage(data.content, data.user, data.msgID, "confirmed");
                                        } else if (data.type === 'join-room') {
                                            if (data.success) {
                                                console.log("Joined room: " + data.room)
                                                hideLoginCover();
                                                function getCount(parent, getChildrensChildren){
                                                    var relevantChildren = 0;
                                                    var children = parent.childNodes.length;
                                                    for(var i=0; i < children; i++){
                                                        if(parent.childNodes[i].nodeType != 3){
                                                            if(getChildrensChildren)
                                                                relevantChildren += getCount(parent.childNodes[i],true);
                                                            relevantChildren++;
                                                        }
                                                    }
                                                    return relevantChildren;
                                                }
                                                var lastCount = 0;
                                                var lastWinHeight = 0;
                                                setInterval(() => {
                                                    if (getCount(messageHolder, false) != lastCount) {
                                                        messageHolder.scrollTop = messageHolder.scrollHeight;
                                                        lastCount = getCount(messageHolder, false);
                                                    }
                                                    if (window.innerHeight != lastWinHeight) {
                                                        messageHolder.style.height = (window.innerHeight - 150).toString() + "px";
                                                        lastWinHeight = window.innerHeight;
                                                    }
                                                }, 120);
                                                messageInputField.addEventListener("keyup", function(event) {
                                                    if (event.keyCode === 13) {
                                                        if (messageInputField.value != '' && lastMsg < (new Date().getTime() - 1000)) {
                                                            var msgid = (Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15)).toUpperCase();
                                                            send({
                                                                type: 'message-send',
                                                                message: messageInputField.value,
                                                                roomid: currentRoomID,
                                                                sessionID: userData.sessionID,
                                                                msgID: msgid
                                                            });
                                                            addMessage(messageInputField.value, userData.displayName, msgid, "inProgress");
                                                            messageInputField.value = '';
                                                            lastMsg = new Date().getTime();
                                                        }
                                                    }
                                                });
                                            }
                                        } else if (data.type === 'user-message-sent') {
                                            if (data.success) {
                                                try {
                                                    document.getElementById(data.msgID).remove()
                                                    addMessage(data.content, data.user, data.msgID, "confirmed");
                                                } catch { }
                                            }
                                        }
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
            }
        } else {
            console.error("Untrusted message received")
        }
    }
}