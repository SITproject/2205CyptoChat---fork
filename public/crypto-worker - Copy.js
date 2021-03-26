self.window = self // This is required for the jsencrypt library to work within the webworker

// Import the jsencrypt library
self.importScripts('https://cdnjs.cloudflare.com/ajax/libs/jsencrypt/2.3.1/jsencrypt.min.js');
self.importScripts('https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.0.0/crypto-js.min.js');
self.importScripts('crypto.js')
self.importScripts('futoin-hkdf.js')
self.importScripts('aes-js.js')
self.importScripts('eccrypto.js')
self.importScripts('buffer-from.js')
self.importScripts('deasync.js')


let crypt = null
let privateKey = null
let ss = null

const crypto = require('crypto')
const eccrypto = require("eccrypto");
const hkdf = require('futoin-hkdf')
const aesjs = require('aes-js');
const bufferFrom = require('buffer-from')
var deasync = require('deasync');
var cp = require('child_process');

/** Webworker onmessage listener */
onmessage = function(e) {
  const [ messageType, messageId, text, key, IV ] = e.data
  let result
  switch (messageType) {
    case 'generate-keys':
      result = generateKeypair()
      break
    case 'encrypt':
      result = encrypt(text, key, IV)
      break
    case 'decrypt':
      result = decrypt(text, key , IV)
      break
	case 'hmac':
	  result = generateHash(text)
	  break
	case 'sign':
	  result = sign(text)
	  break
	case 'unsign':
	  result = unsign(text)
	  break
	case 'sharedSecret':
	  result = sharedSecret(key)
	  break  
	case 'keyDerive':
	  result = keyDerive()
	  break
	case 'generateIV':
	  result = generateIV()
	  break
	case 'bytesToStr':
	  result = bytesToStr(text)
	  break
	case 'strToBytes':
	  result = strToBytes(text)
	  break  
  }

  // Return result to the UI thread
  postMessage([ messageId, result ])
}

/** Generate and store keypair */
function generateKeypair () {
  privateKey = eccrypto.generatePrivate();
  return bytesToStr(eccrypto.getPublic(privateKey))
	
  crypt = crypto.createECDH('secp256k1');
  crypt.generateKeys()
  //console.log(user.getPrivateKey().toString("base64"))
  return crypt.getPublicKey().toString("base64")
  
  //crypt = new JSEncrypt({default_key_size: 2056})
  //privateKey = crypt.getPrivateKey()
  // Only return the public key, keep the private key hidden
  //return crypt.getPublicKey()
}

/** Encrypt the provided string with the destination public key */
function encrypt (content, derivedKey, IV) {
  // Convert text to bytes
  //var key = [ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 ];

// The initialization vector (must be 16 bytes)
  //var iv = [ 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,35, 36 ];
  var textBytes = aesjs.utils.utf8.toBytes(content);
  var aesOfb = new aesjs.ModeOfOperation.ofb(derivedKey, IV);
  var encryptedBytes = aesOfb.encrypt(textBytes);
  var encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
  return encryptedHex
  
}

/** Decrypt the provided string with the local private key */
function decrypt (content, derivedKey, IV) {
  var encryptedBytes = aesjs.utils.hex.toBytes(content);
  var aesOfb = new aesjs.ModeOfOperation.ofb(derivedKey, IV);
  var decryptedBytes = aesOfb.decrypt(encryptedBytes);
  var decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
  return decryptedText
}

//----------------------------------untested---------------
//HKDF
function keyDerive(){
	const ikm = ss;
	const length = 32;
	const salt = crypto.randomBytes(32);
	const info = '';
	const hash = 'SHA-256';
	//console.log(hkdf.extract('ripemd160', 128, ikm, salt)); 
	//return hkdf(ikm, length, salt, info, hash);
	const extract = hkdf.extract('ripemd160', 32, ikm, salt);
	return(hkdf.expand('SHA256', 256, extract, 32, info)); // run only step #2
}

function generateIV(){
	return crypto.randomBytes(16)
}

function signingdata(text){
  const hash = createHash('sha256',privateKey).update(text).digest('hex')
  return hash
}

function sign(content){
	crypt.setKey(privateKey)
	return crypt.encrypt(content)
}

function unsign(content, publicKey){
	crypt.setKey(publicKey)
	return crypt.decrypt(content)
}

function generateHash(content){
  var hash = CryptoJS.SHA256(content);
  return hash.toString();
}

function sharedSecret(kkey){
	const dkey = bufferFrom(strToBytes(kkey))

	//ss = crypt.computeSecret(kkey, 'base64', 'hex');
	//return ss;
}


function Import(path){
  fs = require('fs');
  fs.readFile(path, 'utf8',  function (err,data){
    if (err) {
      return console.log(err);
    }
    console.log(data);
  });
}
function Export(){
  fs = require('fs');
  fs.appendFile('export.txt', 'private key', function (err) {
    if (err) throw err;
    console.log('Saved!');
  });
  fs.appendFile('export.txt', privateKey, function (err) {
    if (err) throw err;
    console.log('Saved!');
  });
  fs.appendFile('export.txt', 'public key', function (err) {
    if (err) throw err;
    console.log('Saved!');
  });
  fs.appendFile('export.txt', publicKey, function (err) {
    if (err) throw err;
    console.log('Saved!');
  });
}
//----------------------------------untested---------------

function bytesToStr(content){
	return aesjs.utils.hex.fromBytes(content);
}

function strToBytes(content){
	return aesjs.utils.hex.toBytes(content);
}