self.window = self // This is required for the jsencrypt library to work within the webworker

// Import the jsencrypt library
self.importScripts('https://cdnjs.cloudflare.com/ajax/libs/jsencrypt/2.3.1/jsencrypt.min.js');
self.importScripts('https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.0.0/crypto-js.min.js');
self.importScripts('crypto.js')
self.importScripts('futoin-hkdf.js')
self.importScripts('aes-js.js')
self.importScripts('eccrypto.js')
self.importScripts('secp256k1.js')
self.importScripts('buffer.js')

let crypt = null
let privateKey = null
let ss = null

const crypto = require('crypto')
const eccrypto = require('eccrypto')
const hkdf = require('futoin-hkdf')
const aesjs = require('aes-js')
const secp256k1 = require('secp256k1')
const Buffer = require('buffer').Buffer

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
	  result = hmacSha256(key ,text)
	  break
	case 'sign':
	  result = sign(text)
	  break
	case 'verifySign':
	  result = verifySign(text, key, IV)
	  break
	case 'sharedSecret':
	  result = sharedSecret(key)
	  break  
	case 'keyDerive':
	  result = keyDerive(text, key)
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
	case 'PKIEncrypt':
	  result = PKIEncrypt(text,key)
	  break
	case 'PKIDecrypt':
	  result = PKIDecrypt(text)
	  break
	case 'generateSalt':
	  result = generateSalt()
	  break
	case 'shuffle':
	  result = shuffle(text,key)
	  break  
  }

  // Return result to the UI thread
  postMessage([ messageId, result ])
}


/** Generate and store keypair */
function generateKeypair () {
  privateKey = eccrypto.generatePrivate();
  //console.log(user.getPrivateKey().toString("base64"))
  return bytesToStr(eccrypto.getPublic(privateKey))
  
}

/** Encrypt the provided string with the destination public key */
function encrypt (content, derivedKey, IV) {
  // Convert text to bytes
  var textBytes = aesjs.utils.utf8.toBytes(content);
  var aesOfb = new aesjs.ModeOfOperation.ofb(derivedKey, IV);
  var encryptedBytes = aesOfb.encrypt(textBytes);
  var encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
  return encryptedHex
  
}

/** Decrypt the provided string with the local private key */
function decrypt (content, derivedKey, IV) {
  //var encryptedBytes = aesjs.utils.hex.toBytes(content);
  var aesOfb = new aesjs.ModeOfOperation.ofb(derivedKey, IV);
  var decryptedBytes = aesOfb.decrypt(content);
  var decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
  return decryptedText
}

//HKDF
function keyDerive(content, saltt){
	if(content == "encryption"){
		const ikm = ss.slice(0,15);		
		const length = 32;
		const salt = saltt;
		const info = '';
		const hash = 'SHA-256';
		const extract = hkdf.extract('ripemd160', 32, ikm, salt);
		return(hkdf.expand('SHA256', 256, extract, 32, info));
	}else{
		const ikm = ss.slice(16,32);		
		const length = 32;
		const salt = saltt;
		const info = '';
		const hash = 'SHA-256';
		const extract = hkdf.extract('ripemd160', 32, ikm, salt);
		return(hkdf.expand('SHA256', 256, extract, 32, info));
	}

}

function generateIV(){
	return crypto.randomBytes(16)
}

function generateSalt(){
	return crypto.randomBytes(32);
}

function sign(content){
	content = pad32(Buffer.from(content));
	var sig = secp256k1.ecdsaSign(content, privateKey).signature;
	return secp256k1.signatureExport(sig)
}

function verifySign(msg, publicKey, sig){
	msg = pad32(Buffer.from(msg));
	sig = secp256k1.signatureImport(sig);
	if (secp256k1.ecdsaVerify(sig, msg, Buffer.from(strToBytes(publicKey)))){
		return 1
	}else{
		return 0
	}
}

function sharedSecret(key){
	const dKey = strToBytes(key)
	const bKey = Buffer.from(dKey)
	ss = secp256k1.ecdh(bKey, privateKey)
}



function bytesToStr(content){
	return aesjs.utils.hex.fromBytes(content);
}

function strToBytes(content){
	return aesjs.utils.hex.toBytes(content);
}


function PKIEncrypt(symkey, pubkey){
	//const dSym = strToBytes(symkey)
	const dKey = strToBytes(pubkey)
	const bSym = Buffer.from(symkey)
	const bKey = Buffer.from(dKey)
	
	//ECIES
	//generate ephemepharal private key
	const ephemPrivateKey = eccrypto.generatePrivate() || crypto.randomBytes(32);
	const ephemPublicKey = eccrypto.getPublic(ephemPrivateKey);
	const ephemSS = secp256k1.ecdh(bKey, ephemPrivateKey)
	const hash = sha512(ephemSS);
	const iv = crypto.randomBytes(16);
	const encryptionKey = hash.slice(0, 32);
	const macKey = hash.slice(32);
	const ciphertext = aes256CbcEncrypt(iv, encryptionKey, bSym);
	const dataToMac = Buffer.concat([iv, ephemPublicKey, ciphertext]);
	const mac = Buffer.from(hmacSha256(macKey, dataToMac));
	return {
      iv: bytesToStr(iv),
      ephemPublicKey: bytesToStr(ephemPublicKey),
      ciphertext: bytesToStr(ciphertext),
      mac: bytesToStr(mac),
    };
}

//Decrypt using Public Private ECC ephemepheral keys
function PKIDecrypt(encrypted){
	const ephemSS = secp256k1.ecdh(Buffer.from(strToBytes(encrypted.ephemPublicKey)), privateKey)
	const hash = sha512(ephemSS);
	const encryptionKey = hash.slice(0, 32);
	const macKey = hash.slice(32);
	const dataToMac = Buffer.concat([
      Buffer.from(strToBytes(encrypted.iv)),
      Buffer.from(strToBytes(encrypted.ephemPublicKey)),
	  Buffer.from(strToBytes(encrypted.ciphertext))
    ]);
	const realMac = hmacSha256(macKey, dataToMac);
	assert(equalConstTime(Buffer.from(strToBytes(encrypted.mac)), realMac), "Bad MAC");
	return aes256CbcDecrypt(Buffer.from(strToBytes(encrypted.iv)), encryptionKey, Buffer.from(strToBytes(encrypted.ciphertext)));
}

function sha512(msg) {
  return crypto.createHash("sha512").update(msg).digest();
}

function aes256CbcEncrypt(iv, key, plaintext) {
  var cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  var firstChunk = cipher.update(plaintext);
  var secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

function aes256CbcDecrypt(iv, key, ciphertext) {
  var cipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  var firstChunk = cipher.update(ciphertext);
  var secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

function hmacSha256(key, msg) {
  return crypto.createHmac("sha256", key).update(msg).digest();
}

function equalConstTime(b1, b2) {
  if (b1.length !== b2.length) {
    return false;
  }
  var res = 0;
  for (var i = 0; i < b1.length; i++) {
    res |= b1[i] ^ b2[i];  // jshint ignore:line
  }
  return res === 0;
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

function pad32(msg){
  var buf;
  if (msg.length < 32) {
    buf = Buffer.alloc(32);
    buf.fill(0);
    msg.copy(buf, 32 - msg.length);
    return buf;
  } else {
    return msg;
  }
}

function shuffle(content, key){
	
	//generate encoding tables domains
	const two_bit_list = ['00', '01', '10', '11']
	const dna_bases = ['A', 'C', 'G', 'T']

	const four_bit_list = ['0000', '0001', '0010', '0011', '0100', '0101', '0110', '0111', '1000', '1001', '1010', '1011', '1100',
					 '1101', '1110', '1111']
	const two_dna_bases = ['TA', 'TC', 'TG', 'TT', 'GA', 'GC', 'GG', 'GT', 'CA', 'CC', 'CG', 'CT', 'AA', 'AC', 'AG', 'AT']

	//encoding tables and their reversal
	const two_bits_to_dna_base_table = {}
	const dna_base_to_two_bits_table = {}

	const four_bits_to_two_dna_base_table = {}
	const two_dna_base_to_four_bits_table = {}
	
	//Decide number of rounds random
	var rounds = Math.floor((Math.random() * 12) + 3)
	
	//zip two_bit_list and dna_bases together
	two_bit_list.forEach((key, i) => two_bits_to_dna_base_table[key] = dna_bases[i])
	
	//Zip DNA base together
	dna_bases.forEach((key, i) => dna_base_to_two_bits_table [key] = two_bit_list[i])
	
	
	//Zip 4 bit list together with 2 DNA bases
	four_bit_list.forEach((key, i) => four_bits_to_two_dna_base_table [key] = two_dna_bases[i])
	
	//Zip 4 bit list together with 2 DNA bases
	two_dna_bases.forEach((key, i) => two_dna_base_to_four_bits_table [key] = four_bit_list[i])
	
	//Binarized data and convert into DNA sequence
	const binarizedData = stringToBinary(content)
	const dna_seq = bits_to_dna(binarizedData, two_bits_to_dna_base_table)
	var binarizedData2 = dna_seq
	
	//256 bits key - convert to binary
	const keyString = byteToString(key)
	const binaryKey = stringToBinary(keyString)

	////////////////////////////////////// decryption_key += no_rounds_del + str(rounds_no) + no_rounds_del
	
	while (rounds > 0){
		//encrypt data with key after reshaping it back to binary sequence and then convert it back to dna sequence
		
		//dna to bits
		const bitsDNA = dna_to_bits(binarizedData2, dna_base_to_two_bits_table)
		const xorData = encrypt_key(bitsDNA, binaryKey)
		const newDNAseq = bits_to_dna(xorData, two_bits_to_dna_base_table)
		
		//Create chromosome population
		const newDNA = reshape(newDNAseq)
		
		//apply crossover on population
		//decryption_key += crossover_del
        b_data2 = crossover(b_data2)
        //decryption_key += crossover_del
		rounds = rounds - 1
	}
}

function reshape(dna_seq){
	const div = divisors(dna_seq.length)
	const random = getRandomInt(0, div.length - 1)
	const chromosome_no = div[random]
	const chromosome_length = parseInt(dna_seq.length / chromosome_no, 10)
	var chromosomes = []
	////////////////////////////////////// decryption_key += reshape_del + str(chromosome_length) + reshape_del
	
	for (var i = 0; i < dna_seq.length; i += chromosome_length){
		chromosomes.push(dna_seq.substring(i, i+chromosome_length))
	}
	return chromosomes
	
}

function divisors(n){
	// Get the divisors of a natural number.
	var div = []
	for(var i = 2; i < Math.floor(Math.sqrt(n)) + 1; i ++){
		if(n % i == 0){
			div.push(i, n/i)
		}
	}
	console.log(n)
	console.log(div)
	var tempSet = new Set(div)
	return Array.from(tempSet)
}

function bitxor(a, b){
	//xor data
	var data='';
	
	for (var i = 0; i < a.length; i++) {
		var numberA = parseInt(a.charAt(i), 10)
		var numberB = parseInt(b.charAt(i), 10)
		var xorNum = numberA ^ numberB
		var strXor = xorNum.toString();
		data += strXor
	}
	return data
}

function encrypt_key(data, key){
	//repeat key only if data is longer than key and xor encrypt
	if(data.length > key.length){
		var factor =  Math.floor(data.length/key.length)
		key += key * factor
		return bitxor(data, key)
	}
	return bitxor(data, key)
}

function dna_to_bits(bData, table){
	var dnabits = '';
	for (var i = 0; i < bData.length; i++) {
		dnabits += table[bData.charAt(i)]
	}
	return dnabits
}

function bits_to_dna(bData, table){
	var dna = '';
	for (var i = 0; i < bData.length-1; i++) {
		dna += table[bData.charAt(i) +bData.charAt(i+1)]
	}
	return dna
}

function stringToBinary(input) {
  var characters = input.split('');

  return characters.map(function(char) {
    const binary = char.charCodeAt(0).toString(2)
    const pad = Math.max(8 - binary.length, 0);
    // Just to make sure it is 8 bits long.
    return '0'.repeat(pad) + binary;
  }).join('');
}

function binaryToString(input) {
  let bytesLeft = input;
  let result = '';

  // Check if we have some bytes left
  while (bytesLeft.length) {
    // Get the first digits
    const byte = bytesLeft.substr(0, 8);
    bytesLeft = bytesLeft.substr(8);

    result += String.fromCharCode(parseInt(byte, 2));
  }

  return result;
}

function byteToString(input){
	return String.fromCharCode(...Array.from(input))
}

function stringToByte(input){
  var encode = []
  
  for (var i = 0; i < input.length; i++) {
	  encode.push(input.charAt(i).charCodeAt(0))
  } 
  return encode
}

function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min) + min);
}