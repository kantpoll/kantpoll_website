/**
 * Kantpoll Project
 * https://github.com/kantpoll
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/******************** Constants ********************/
//Special string
const THE_AND = "--and--";

//Standard responses from the server
const ERROR_STRING = "error";

//Minimum password length
const PASSWORD_MIN_LENGTH = 8;
//It is used to call the methods fromAscii and toAscii
const web3_aux = new Web3();

//Algorithm used to encrypt tor requests
const ENCRYPT_ALGORITHM_RSA = {
    name: "RSA-OAEP",
    modulusLength: 1024,
    publicExponent: new Uint8Array([1, 0, 1]),
    extractable: false,
    hash: {
        name: "SHA-256"
    }
};

/********************* Global variables *************************/
//localhost:1985
let using_local_server = isUsingLocalServer();

//Localhost or 127.0.0.1 ? (or neither)
let localhost127 = (window.location.href.startsWith("http://localhost") ? "localhost" : "127.0.0.1");

//To be used in place of the localStorage
let secureStorage = {get: function(){ return ""}, set: function(){}, remove: function(){}};
setSecureStorage();

//Wallet to interact with Geth
let wallet = {};

//Wallet to send the pre-vote
let prevoter_wallet = {};

/********************  jQuery configurations ********************/

$(document).ready(function () {
    $('.aniview').AniView();
    $('.carousel.carousel-slider').carousel({
        fullWidth: true,
        indicators: true
    });
    $('.modal').modal({dismissible: false});
    $('.parallax').parallax();
});

/******************** Event listeners ********************/

/**
 *  Setting some variables
 */
window.addEventListener("load", function () {
    let locale = "en";
    if (navigator.language) {
        locale = navigator.language.substring(0, 2).toLowerCase()
    }

    if (locale == 'pt') {
        klang = klang.portuguese
    } else if (locale == 'fr') {
        klang = klang.french
    } else if (locale == 'es') {
        klang = klang.spanish
    } else {
        klang = klang.english
    }

    login_download.innerHTML = klang.login_download;
    login_title.innerHTML = klang.login_title;
    login_message.innerHTML = klang.login_message;
    login_create_button.innerHTML = klang.login_create_button;
    modal2_title.innerHTML = klang.modal2_title;
    modal2_file_name.innerHTML = klang.modal2_file_name;
    modal2_save.text = klang.modal2_save;
    modal2_certificate.innerHTML = klang.modal2_certificate;
    modal4_title.innerHTML = klang.modal4_title;
    modal4_user.innerHTML = klang.modal1_user;
    modal4_password1.innerHTML = klang.modal4_password1;
    modal4_password2.innerHTML = klang.modal4_password2;
    modal4_confirm.text = klang.modal4_confirm;
    modal5_title.innerHTML = klang.modal5_title;
    modal5_certificate_authority_url.innerHTML = klang.certificate_authority_url;
    modal5_send.text = klang.modal5_send;
    modal5_skip.text = klang.modal5_skip;
    privacy_link.innerHTML = klang.privacy;
    motto_label.innerHTML = klang.login_title;
    resources_label.innerHTML = klang.resources;
    contact_link.innerHTML = klang.contact;
    conduct_link.innerHTML = klang.conduct;
    license_link.innerHTML = klang.license;
    for_whom_label.innerHTML = klang.for_whom_label;
    polling_org_label.innerHTML = klang.polling_org_label;
    unions_label.innerHTML = klang.unions_label;
    parties_label.innerHTML = klang.parties_label;
    universities_label.innerHTML = klang.universities_label;
    schools_label.innerHTML = klang.schools_label;
    municipalities_label.innerHTML = klang.municipalities_label;
    many_more_label.innerHTML = klang.many_more_label;
    easy_voters_label.innerHTML = klang.easy_voters_label;
    easy_voters_text.innerHTML = klang.easy_voters_text;
    promising_technologies_label.innerHTML = klang.promising_technologies_label;
    promising_technologies_text.innerHTML = klang.promising_technologies_text;
    simple_campaigns_label.innerHTML = klang.simple_campaigns_label;
    acknowledgment_link.innerHTML = klang.acknowledgment;
    or_go_to_span.innerHTML = klang.or_go_to_span;

    //It works with home or home.html
    go_to_home.href = window.location.href.replace("login", "home");

    //Setting the data-tooltip of the password input
    let aElementP1 = $('#password_div1');
    aElementP1.attr('data-tooltip', klang.min_chars);
    aElementP1.tooltip();

    //Setting the data-tooltip of the user input
    let aElementP2 = $('#user_div1');
    aElementP2.attr('data-tooltip', klang.hyphen);
    aElementP2.tooltip();

    if (detectIE()) {
        buttons_div.innerHTML = browser_not_supported_div.innerHTML.replace("<!--[CDATA[", "").replace("-->", "");
        browser_not_supported_label.innerHTML = klang.browser_not_supported_label
    }
});

modal4_confirm.addEventListener("click", function () {
    let password3 = kantpoll_com_password3.value;
    let password4 = kantpoll_com_password4.value;
    let user = kantpoll_com_user3.value;

    createVault(password3, password4, user)
});

modal2_save.addEventListener("click", function () {
    saveVault(file_name1.value)
});

modal5_send.addEventListener("click", sendVault);

/**
 * It displays a JQCloud with all the open source projects used in this project
 */
acknowledgment_link.addEventListener("click", showThanks);

file_name1.addEventListener("keypress", function (event) {
    let keyCode = event.keyCode;
    if (keyCode == 13) {
        modal2_save.click()
    }
});

kantpoll_com_password4.addEventListener("keypress", function (event) {
    let keyCode = event.keyCode;
    if (keyCode == 13) {
        modal4_confirm.click()
    }
});

/**
 * These functions paint the password underline red in case of wrong password input
 */
kantpoll_com_password4.addEventListener("focusout", function () {
    if (kantpoll_com_password4.value && kantpoll_com_password3.value) {
        if (kantpoll_com_password3.value != kantpoll_com_password4.value ||
            kantpoll_com_password4.value < PASSWORD_MIN_LENGTH) {
            kantpoll_com_password4.style = "border-bottom: 1px solid red;"
        } else {
            kantpoll_com_password4.style = "border-bottom: 1px solid green;"
        }
    } else {
        kantpoll_com_password4.style = "border-bottom: 1px bold grey;"
    }
});

kantpoll_com_password4.addEventListener("mouseout", function () {
    if (kantpoll_com_password4.value && kantpoll_com_password3.value) {
        if (kantpoll_com_password3.value != kantpoll_com_password4.value ||
            kantpoll_com_password4.value < PASSWORD_MIN_LENGTH) {
            kantpoll_com_password4.style = "border-bottom: 1px solid red;"
        } else {
            kantpoll_com_password4.style = "border-bottom: 1px solid green;"
        }
    } else {
        kantpoll_com_password4.style = "border-bottom: 1px bold grey;"
    }

});

kantpoll_com_password3.addEventListener("focusout", function () {
    if (kantpoll_com_password3.value) {
        if (kantpoll_com_password3.value.length >= PASSWORD_MIN_LENGTH) {
            kantpoll_com_password3.style = "border-bottom: 1px solid bluegreen;"
        } else {
            kantpoll_com_password3.style = "border-bottom: 1px solid red;"
        }
    } else {
        kantpoll_com_password3.style = "border-bottom: 1px bold grey;"
    }
});

kantpoll_com_password3.addEventListener("mouseout", function () {
    if (kantpoll_com_password3.value) {
        if (kantpoll_com_password3.value.length >= PASSWORD_MIN_LENGTH) {
            kantpoll_com_password3.style = "border-bottom: 1px solid bluegreen;"
        } else {
            kantpoll_com_password3.style = "border-bottom: 1px solid red;"
        }
    } else {
        kantpoll_com_password3.style = "border-bottom: 1px bold grey;"
    }
});

/******************** Functions ********************/

/**
 * It displays a JQCloud with all the open source projects used in this project
 */
function showThanks() {
    let words = [
        {text: "Kantpoll", weight: 8, link: "https://github.com/kantpoll"},
        {text: "Ethereum", weight: 6, link: "https://www.ethereum.org"},
        {text: "Tor", weight: 6, link: "https://www.torproject.org/projects/torbrowser.html"},
        {text: "IPFS", weight: 6, link: "https://ipfs.io"},
        {text: "URS", weight: 6, link: "https://github.com/monero-project/urs"},
        {text: "Bolt", weight: 6, link: "https://github.com/boltdb/bolt"},
        {text: "Materialize", weight: 6, link: "http://materializecss.com"},
        {text: "Aniview", weight: 2, link: "https://github.com/jjcosgrove/jquery-aniview"},
        {text: "Animatecss", weight: 2, link: "https://github.com/daneden/animate.css/"},
        {text: "Golang", weight: 4, link: "https://golang.org"},
        {text: "Web3.js", weight: 6, link: "https://github.com/ethereum/web3.js/"},
        {text: "Sheet JS", weight: 6, link: "https://github.com/SheetJS/js-xlsx"},
        {text: "JQCloud", weight: 3, link: "https://github.com/lucaong/jQCloud"},
        {text: "Account Kit", weight: 6, link: "https://developers.facebook.com/docs/accountkit"},
        {text: "Bip39", weight: 3, link: "https://github.com/bitcoinjs/bip39"},
        {text: "js-sha256", weight: 3, link: "https://github.com/emn178/js-sha256"},
        {text: "js-sha3", weight: 3, link: "https://github.com/emn178/js-sha3"},
        {text: "ethers.js", weight: 6, link: "https://github.com/ethers-io/ethers.js/"},
        {text: "JQuery", weight: 3, link: "https://jquery.com"},
        {text: "SecureLS", weight: 3, link: "https://github.com/softvar/secure-ls"},
        {text: "cryptocoinjs", weight: 4, link: "https://github.com/cryptocoinjs"},
        {text: "go-jwx", weight: 2, link: "https://github.com/lestrrat/go-jwx"},
    ];

    acknowledgment_div.innerHTML = acknowledgment_html.innerHTML.replace("<!--[CDATA[", "").replace("-->", "")
        .replace("[[thanks]]", klang.thanks_community);

    sleep(600).then(function () {
        $('#word_cloud').jQCloud(words)
    })
}

/**
 * It generates a file with the user's mnemonics and a hash
 * @param {string} file
 */
function saveVault(file) {
    //Getting the mnemonics from local storage
    let words = localStorage.getItem("words");

    //Creating Ekhash in order to check user login and password
    let ekhash = localStorage.getItem("ekhash");

    //Checking if there are words to be saved and if the file name was provided
    if (!words || !file || !ekhash) {
        toast(klang.no_vault_saved, 3000, 'rounded');
        return
    }

    secureStorage.set("my_certificate", certificate_input.value);

    //The data should be formatted as a JSON string
    let data = '{'
        + '"certificate":' + certificate_input.value + ','
        + '"ekhash":"' + ekhash + '",'
        + '"rsa_privkey":"' + secureStorage.get("rsa_privkey") + '",'
        + '"rsa_pubkey":"' + secureStorage.get("rsa_pubkey") + '"'
        + '}';

    let hex_data = web3_aux.fromAscii(data);

    //Removing the prefix in order to difficult file location by this string
    //Saving the mnemonics and data
    let blob = new Blob([words + "\r\n" + hex_data], {type: "text/plain;charset=utf-8"});

    file_saver.href = URL.createObjectURL(blob);
    file_saver.download = file;
    file_saver.click();

    let new_location = window.location.href.split("#")[0];
    window.location.href = new_location.replace("login", "home")
}

/**
 * It sends the public key and the user id to the login provider
 */
function sendVault() {
    let user = localStorage.getItem("user");
    let ca_link = ca_link_input.value;

    if (!user || !wallet.address) {
        toast(klang.no_vault_opened, 3000, 'rounded');
        return
    }

    let x = (screen.width / 2) - 220;
    let y = (screen.height / 2) - 300;

    child = window.open("", "_blank", "width=440,height=600,top=" + y + ",left=" + x +
        ",resizable=no,status=no,menubar=no,scrollbars=yes,titlebar=no,toolbar=no");
    if (child.location.href) {
        child.location.href = ca_link + "?address=" + wallet.address.replace("0x", "") + "&id=" + user
    } else {
        child.location = ca_link + "?address=" + wallet.address.replace("0x", "") + "&id=" + user
    }
}

/**
 * It creates a new vault, but it does not save it into a file
 * @param {string} password3
 * @param {string} password4
 * @param {string} user
 */
function createVault(password3, password4, user) {
    //Checking if empty
    if (!password3 || !password4 || !user) {
        toast(klang.empty_fields, 3500, 'rounded');
        return
    }

    //Checking if passwords match
    if (password3 != password4) {
        toast(klang.different_passwords, 3500, 'rounded');
        return
    }

    //Verifying the password length
    if (password3.length < PASSWORD_MIN_LENGTH) {
        toast(klang.password_too_small, 4000, 'rounded');
        return
    }

    //Former user's data erased
    localStorage.clear();

    let m = new Mnemonic("english");

    // Generating new mnemonics
    let words = m.generate(128);

    generateKeys(words, password3, user);

    //Creating Ekhash in order to check user login and password (only informative, without safety concerns)
    let ekhash = keccak224(sessionStorage.getItem("key") + user);

    //Setting the ekhash in the localStorage
    localStorage.setItem("ekhash", ekhash);

    //Setting the ekhash in the localStorage
    localStorage.setItem("words", words);

    //Setting the user in the localStorage
    localStorage.setItem("user", user);

    //Closing the modal
    $('#modal4').modal('close');

    //Cleaning the fields
    kantpoll_com_password3.value = "";
    kantpoll_com_password4.value = "";
    kantpoll_com_user3.value = "";

    $('#modal5').modal('open')
}

/**
 * It generates the main key, the aux public key and the wallet
 * @param {string} words
 * @param {string} password
 * @param {string} user
 * @returns {Object}
 */
function generateKeys(words, password, user) {
    //Using bitcoinjs-lib to generate a privatekey from the mnemonics and the password
    //This key is used to sign and verify ring signatures
    let seed = ethers.HDNode.mnemonicToSeed(words + ' ' + user + ' ' + password);
    let hdMaster = ethers.HDNode.fromSeed(seed);
    let seed2 = ethers.HDNode.mnemonicToSeed(words + ' ' + keccak224(user) + ' ' + keccak224(password));
    let hdMaster2 = ethers.HDNode.fromSeed(seed2);

    let keys = {};
    keys[0] = hdMaster.derivePath('m/0/0');
    keys[1] = hdMaster.derivePath('m/0/1');
    keys[2] = hdMaster2.derivePath('m/0/0');
    keys[3] = hdMaster2.derivePath('m/0/1');
    keys[4] = hdMaster2.derivePath('m/0/2');
    keys[5] = hdMaster2.derivePath('m/0/3');

    let aux_signingkey = new ethers.SigningKey(keys[0].privateKey);
    let pubkey = aux_signingkey.publicKey.substring(2);
    let address = aux_signingkey.address.substring(2);

    let keyjson = "{\"address\":\"" + address + "\",\"privkey\":\"" + keys[0].privateKey.substring(2) +
        "\",\"pubkey\":\"" + pubkey + "\"}";
    sessionStorage.setItem("key", keyjson);

    //Wallet to interact with Geth
    wallet = new ethers.Wallet(keys[1].privateKey);
    sessionStorage.setItem("wallet", JSON.stringify(wallet));

    //To send pre-votes
    prevoter_wallet = new ethers.Wallet(keys[2].privateKey);
    sessionStorage.setItem("prevoter_wallet", JSON.stringify(prevoter_wallet));

    sessionStorage.setItem("directory_seed", keccak224(keys[3].privateKey));
    sessionStorage.setItem("pwd_seed", keccak224(keys[4].privateKey));
    sessionStorage.setItem("usershash_seed", keccak224(keys[5].privateKey));

    setSecureStorage();
    setRSAKeys(function () {
        if (using_local_server) {
            //Only one admin session is necessary
            setSessionCode()
        }
    });

    return wallet.address.replace("0x", "")
}

/**
 * Sleep/Delay
 * @returns {Promise}
 */
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * It shows a 'toast' when using a GUI or print the message in the console
 * @param {string} msg
 * @param {number} duration
 */
function toast(msg, duration) {
    Materialize.toast(msg, duration, 'rounded')
}

/**
 * The RSA keys are used to decrypt messages received via tor
 * @param {function} callback
 */
function setRSAKeys(callback) {
    generateRSAKeys().then(function (keys) {
        exportRSAPemKeys(keys).then(function (result) {
            secureStorage.set("rsa_pubkey", result.publicKey.replace(/\r\n/g, THE_AND));
            secureStorage.set("rsa_privkey", result.privateKey.replace(/\r\n/g, THE_AND));

            if(callback){
                callback()
            }
        })
    })
}

/**
 * It allow users to encrypt/decrypt data stored in the LocalStorage
 */
function setSecureStorage(){
    if (sessionStorage.getItem("key")) {
        let key = JSON.parse(sessionStorage.getItem("key"));
        secureStorage = new SecureLS({
            encodingType: 'aes', isCompression: false,
            encryptionSecret: keccak224(key.privkey)
        });
    }
}

/**
 * It returns version of IE or false, if browser is not Internet Explorer
 */
function detectIE() {
    var ua = window.navigator.userAgent;

    var msie = ua.indexOf('MSIE ');
    if (msie > 0) {
        // IE 10 or older => return version number
        return parseInt(ua.substring(msie + 5, ua.indexOf('.', msie)), 10)
    }

    var trident = ua.indexOf('Trident/');
    if (trident > 0) {
        // IE 11 => return version number
        var rv = ua.indexOf('rv:');
        return parseInt(ua.substring(rv + 3, ua.indexOf('.', rv)), 10)
    }

    var edge = ua.indexOf('Edge/');
    if (edge > 0) {
        // Edge (IE 12+) => return version number
        return parseInt(ua.substring(edge + 5, ua.indexOf('.', edge)), 10)
    }

    // other browser
    return false
}

/**
 * Some functions are only called when using local server
 * @returns {boolean}
 */
function isUsingLocalServer() {
    return (window.location.href.startsWith("http://localhost:1985") ||
        window.location.href.startsWith("http://127.0.0.1:1985"))
}

/**
 * Only one admin session may interact with the server
 */
function setSessionCode() {
    if (!secureStorage.get("rsa_privkey")) {
        return
    }

    let request = new XMLHttpRequest();
    request.addEventListener("load", function () {
        if (this.responseText != ERROR_STRING && this.responseText != "") {
            let cipher_text = web3_aux.toAscii(this.responseText);
            let cipher_text_bytes = textToArrayBuffer(cipher_text);
            let priv_pem = secureStorage.get("rsa_privkey").replace(new RegExp(THE_AND, 'g'), "\r\n");

            importRSAPrivateKey(priv_pem).then(function (key) {
                RSADecrypt(key, cipher_text_bytes).then(function (code) {
                    secureStorage.set("adminSessionCode", arrayBufferToText(code))
                })
            })
        }
    });

    let rsa = web3_aux.fromAscii(secureStorage.get("rsa_pubkey").replace(new RegExp(THE_AND, 'g'), "\r\n"));
    rsa = rsa.replace("0x", "");
    request.open("GET", "http://" + localhost127 + ":1985/queryNewSession?rsa=" + rsa, true);
    request.send()
}

/************************** RSA tools *******************************/

function generateRSAKeys() {
    return new Promise(function(resolve) {
        var genkey = crypto.subtle.generateKey(ENCRYPT_ALGORITHM_RSA, true, ["encrypt", "decrypt"]);
        genkey.then(function (pair) {
            resolve(pair)
        })
    })
}

function arrayBufferToBase64String(arrayBuffer) {
    var byteArray = new Uint8Array(arrayBuffer);
    var byteString = '';
    for (var i=0; i<byteArray.byteLength; i++) {
        byteString += String.fromCharCode(byteArray[i])
    }
    return btoa(byteString)
}

function convertBinaryToPem(binaryData, label) {
    var base64Cert = arrayBufferToBase64String(binaryData);
    var pemCert = "-----BEGIN " + label + "-----\r\n";
    var nextIndex = 0;
    var lineLength;
    while (nextIndex < base64Cert.length) {
        if (nextIndex + 64 <= base64Cert.length) {
            pemCert += base64Cert.substr(nextIndex, 64) + "\r\n"
        } else {
            pemCert += base64Cert.substr(nextIndex) + "\r\n"
        }
        nextIndex += 64
    }
    pemCert += "-----END " + label + "-----\r\n";
    return pemCert
}

function exportRSAPublicKey(keys) {
    return new Promise(function(resolve) {
        window.crypto.subtle.exportKey('spki', keys.publicKey).
        then(function(spki) {
            resolve(convertBinaryToPem(spki, "RSA PUBLIC KEY"))
        })
    })
}

function exportRSAPrivateKey(keys) {
    return new Promise(function(resolve) {
        var expK = window.crypto.subtle.exportKey('pkcs8', keys.privateKey);
        expK.then(function(pkcs8) {
            resolve(convertBinaryToPem(pkcs8, "RSA PRIVATE KEY"))
        })
    })
}

function exportRSAPemKeys(keys) {
    return new Promise(function(resolve) {
        exportRSAPublicKey(keys).then(function(pubKey) {
            exportRSAPrivateKey(keys).then(function(privKey) {
                resolve({publicKey: pubKey, privateKey: privKey})
            })
        })
    })
}

function base64StringToArrayBuffer(b64str) {
    let byteStr = atob(b64str);
    let bytes = new Uint8Array(byteStr.length);
    for (let i = 0; i < byteStr.length; i++) {
        bytes[i] = byteStr.charCodeAt(i)
    }
    return bytes.buffer
}

function textToArrayBuffer(str) {
    let bufView = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        bufView[i] = str.charCodeAt(i)
    }
    return bufView
}

function arrayBufferToText(arrayBuffer) {
    let byteArray = new Uint8Array(arrayBuffer);
    let str = '';
    for (let i = 0; i < byteArray.byteLength; i++) {
        str += String.fromCharCode(byteArray[i])
    }
    return str
}

function convertPemToBinary(pem) {
    let lines = pem.split('\n');
    let encoded = '';
    for(let i = 0;i < lines.length;i++){
        if (lines[i].trim().length > 0 &&
            lines[i].indexOf('-BEGIN RSA PRIVATE KEY-') < 0 &&
            lines[i].indexOf('-BEGIN RSA PUBLIC KEY-') < 0 &&
            lines[i].indexOf('-END RSA PRIVATE KEY-') < 0 &&
            lines[i].indexOf('-END RSA PUBLIC KEY-') < 0) {
            encoded += lines[i].trim()
        }
    }
    return base64StringToArrayBuffer(encoded)
}

function importRSAPrivateKey(pemKey) {
    return new Promise(function(resolve) {
        let importer = crypto.subtle.importKey("pkcs8", convertPemToBinary(pemKey), ENCRYPT_ALGORITHM_RSA, true, ["decrypt"]);
        importer.then(function(key) {
            resolve(key)
        })
    })
}

function RSADecrypt(key, data) {
    return crypto.subtle.decrypt(
        {
            name: "RSA-OAEP"
        },
        key,
        data
    )
}