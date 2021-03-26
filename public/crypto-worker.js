self.window = self // This is required for the jsencrypt library to work within the webworker

// Import the jsencrypt library
self.importScripts('https://cdnjs.cloudflare.com/ajax/libs/jsencrypt/2.3.1/jsencrypt.min.js');
self.importScripts('https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.0.0/crypto-js.min.js');
self.importScripts('crypto.js')

let crypt = null
let privateKey = null
let ss = null
const crypto = require('crypto')

/** Webworker onmessage listener */
onmessage = function(e) {
  const [ messageType, messageId, text, key ] = e.data
  let result
  switch (messageType) {
    case 'generate-keys':
      result = generateKeypair()
      break
    case 'encrypt':
      result = encrypt(text, key)
      break
    case 'decrypt':
      result = decrypt(text)
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
  }

  // Return result to the UI thread
  postMessage([ messageId, result ])
}

/** Generate and store keypair */
function generateKeypair () {
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
function encrypt (content, publicKey) {
  crypt.setKey(publicKey)
  return crypt.encrypt(content)
}

/** Decrypt the provided string with the local private key */
function decrypt (content) {
  crypt.setKey(privateKey)
  return crypt.decrypt(content)
}

//----------------------------------untested---------------
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

function sharedSecret(key){
	ss = crypt.computeSecret(key, 'base64', 'hex');
	return ss;
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