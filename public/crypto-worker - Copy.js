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
let key_del = "<key>"
let no_rounds_del = "<no_rounds>"
let round_del = "<round>"
let reshape_del = "<reshape>"
let crossover_del = "<crossover>"
let crossover_type_del = "<type>"
let single_point_crossover_del = "<single_point>"
let rotate_crossover_del = "<rotate>"
let rotation_offset_del = "<rotation_offset>"
let rotation_types_del = "<rotation_types>"
let mutation_del = "<mutation>"
let complement_mutation_del = "<complement_mutation>"
let alter_mutation_del = "<alter_mutation>"
let mutation_table_del = "<mutation_table>"
let chromosome_del = "<chromosome>"
let decryption_key = ""
let chromosome_length = 0
let two_bits_to_dna_base_table = {}
let dna_base_to_two_bits_table = {}
let four_bits_to_two_dna_base_table = {}
let two_dna_base_to_four_bits_table = {}



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
	case 'DNA_decrypt':
	  result = DNA_decrypt(text,key)
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

/* --------------------------------------- DNA CRYPTOGRAPHY ENCRYPT --------------------------------------- */

function shuffle(content, key){
	
	//generate encoding tables domains
	const two_bit_list = ['00', '01', '10', '11']
	const dna_bases = ['A', 'C', 'G', 'T']

	const four_bit_list = ['0000', '0001', '0010', '0011', '0100', '0101', '0110', '0111', '1000', '1001', '1010', '1011', '1100',
					 '1101', '1110', '1111']
	const two_dna_bases = ['TA', 'TC', 'TG', 'TT', 'GA', 'GC', 'GG', 'GT', 'CA', 'CC', 'CG', 'CT', 'AA', 'AC', 'AG', 'AT']

	//encoding tables and their reversal

	
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
	console.log(stringToBinary(content))
	const binarizedData = group_bits(stringToBinary(content))
	const dna_seq = bits_to_dna(binarizedData, two_bits_to_dna_base_table)
	var binarizedData2 = dna_seq
	
	//256 bits key - convert to binary
	const keyString = byteToString(key)
	const binaryKey = stringToBinary(keyString)

	decryption_key += key_del + binaryKey + key_del
	decryption_key += no_rounds_del + rounds.toString() + no_rounds_del
	
	var mutatedData;
	
	while (rounds > 0){
		//encrypt data with key after reshaping it back to binary sequence and then convert it back to dna sequence
		decryption_key += round_del
		
		//dna to bits
		const bitsDNA = dna_to_bits(binarizedData2, dna_base_to_two_bits_table)
		const xorData = encrypt_key(bitsDNA, binaryKey)	
		const groupedBits = group_bits(xorData)
		const newDNAseq = bits_to_dna(groupedBits, two_bits_to_dna_base_table)
		
		//Create chromosome population
		const newDNA = reshape(newDNAseq)
		
		//apply crossover on population
		decryption_key += crossover_del
        const crossoverData = crossover(newDNA)
        decryption_key += crossover_del
		
		//apply mutation
		decryption_key += mutation_del
        mutatedData = mutation(crossoverData)
        decryption_key += mutation_del
		
		rounds = rounds - 1
		
		decryption_key += round_del
	}
	
	return {
		data: reverse_reshape(mutatedData),
		key: decryption_key,
	};
}

function mutation(population){
	const bases = ['A', 'C', 'G', 'T']
	const alter_dna_table = alter_dna_bases(bases) 
	decryption_key += mutation_table_del + JSON.stringify(alter_dna_table) + mutation_table_del
	
	new_population = []
	
	for(var i in population){
		decryption_key += chromosome_del
		var b_chromosome = dna_to_bits(population[i], dna_base_to_two_bits_table)
		decryption_key += complement_mutation_del
		var point1 = getRandomInt(0, b_chromosome.length - 1)
        var point2 = getRandomInt(point1, b_chromosome.length - 1)
        decryption_key += "(" + point1.toString() + ", " + point2.toString() + ")"
        decryption_key += complement_mutation_del		
		const newBChrome = complement(b_chromosome, point1, point2)
		
		// convert each 4 bits in chromosome to two dna bases using four_bits_to_two_dna_base_table
        var four_bits_vector = group_bits(newBChrome, 4)
		
		var last_dna_base = null
		
		if((four_bits_vector[four_bits_vector.length - 1]).length == 2){
			last_dna_base = two_bits_to_dna_base_table[four_bits_vector[four_bits_vector.length - 1]]
			//convert only the 4 bits elements
            four_bits_vector.splice(-1,1)
		}
		var dna_seq = bits_to_dna(four_bits_vector, four_bits_to_two_dna_base_table)
		
		if(last_dna_base != null){
			dna_seq += last_dna_base
		}
		
		//and then alter the dna bases between point1 and point2
		decryption_key += alter_mutation_del
		point1 = getRandomInt(0, dna_seq.length - 1)
		point2 = getRandomInt(point1, dna_seq.length - 1)
		decryption_key += "(" + point1.toString() + ", " + point2.toString() + ")"
		decryption_key += alter_mutation_del
        var new_chromosome = ""
		for(var i = 0; i < dna_seq.length; i++){
			if(i >= point1 && i <= point2){
				new_chromosome += alter_dna_table[dna_seq[i]]
			}else{
				new_chromosome += dna_seq[i]
			}
		}
		new_population.push(new_chromosome)
		decryption_key += chromosome_del
	}
	return new_population
}

function complement(chromosome, point1, point2){
	//Flip chromosome bits between point1 and point2.
	var new_chromosome = ""
	
	for (var i = 0 ; i < chromosome.length; i ++){
		if(i >= point1 && i <= point2){
			if(chromosome[i] == '0'){
				new_chromosome += '1'
			}else{
				new_chromosome += '0'
			}
		}else{
			new_chromosome += chromosome[i]
		}
	}
	return new_chromosome
}

function crossover(population){
	const p = Math.random(0,1)
	
	if(p < 0.33){
		decryption_key += crossover_type_del + "rotate_crossover" + crossover_type_del
		return rotate_crossover(population)
	}
	else if ( p >= 0.33 && p < 0.66){
		decryption_key += crossover_type_del + "single_point_crossover" + crossover_type_del
        return single_point_crossover(population)
	}else{
		decryption_key += crossover_type_del + "both" + crossover_type_del
        population = rotate_crossover(population)
        return single_point_crossover(population)
	}
}

function single_point_crossover(population){
	 decryption_key += single_point_crossover_del
	 const new_population = []
	 for (var i = 0; i < population.length - 1; i+=2){
		const candidate1 = population[i]
        const candidate2 = population[i + 1]
		
		const length = candidate1.length
        const crossover_point = getRandomInt(0,length - 1)
		
		decryption_key += crossover_point.toString() + "|"
		
		offspring1 = candidate2.substring(0, crossover_point) + candidate1.substring(crossover_point, candidate1.length)
        offspring2 = candidate1.substring(0, crossover_point) + candidate2.substring(crossover_point, candidate2.length)
        new_population.push(offspring1)
        new_population.push(offspring2)
	 }
	if(population.length % 2 == 1){
		new_population.push(population[population.length-1])
	}
	
	decryption_key += single_point_crossover_del

    return new_population
}

function rotate_crossover(population){
	var new_population = []
	decryption_key += rotate_crossover_del
	
	const rotation_offset = getRandomInt(1, chromosome_length)
	decryption_key += rotation_offset_del + rotation_offset.toString() + rotation_offset_del

    decryption_key += rotation_types_del
	for(var i in population){
		const p = Math.random(0,1)
		if(p > 0.5){
            decryption_key += "right|"
			right_first = population[i].substring(0, population[i].length - rotation_offset)
			right_second = population[i].substring(population[i].length - rotation_offset, population[i].length)
            new_population.push(right_second + right_first)
		}else{
			decryption_key += "left|"
            left_first = population[i].substring(0, rotation_offset)
            left_second = population[i].substring(rotation_offset, population[i].length)		
            new_population.push(left_second + left_first)
		}
	}
	decryption_key += rotation_types_del

    decryption_key += rotate_crossover_del
	return new_population
}

function reshape(dna_seq){
	const div = divisors(dna_seq.length)
	
	const random = getRandomInt(0, div.length - 1)
	const chromosome_no = div[random]
	chromosome_length = parseInt(dna_seq.length / chromosome_no, 10)
	var chromosomes = []
	decryption_key += reshape_del + chromosome_length.toString() + reshape_del
	//console.log(dna_seq)
	for (var i = 0; i < dna_seq.length; i += chromosome_length){
		chromosomes.push(dna_seq.substring(i, i+chromosome_length))
	}
	//console.log(chromosomes)
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
		key += key.repeat(factor)

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
	
	for( var i in bData){
		dna += table[bData[i]]
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

function alter_dna_bases(bases){
	//Alter DNA bases to another one randomly.(e.g. C->G and A->T and viceversa)
	var alter_dna_table = {}
	
	for(var i = 0; i < 2; i++){
		const base1Rand = getRandomInt(0, bases.length - 1)
		const base1 = bases[base1Rand]
        bases.splice(base1Rand, 1);
		
		const base2Rand = getRandomInt(0, bases.length - 1)
		const base2 = bases[base2Rand]
        bases.splice(base2Rand, 1);

		alter_dna_table[base1] = base2
		alter_dna_table[base2] = base1
	}
	return alter_dna_table
}

function group_bits(byte, step=2){
	var bits_group = []
	for (var i =0 ; i < byte.length; i += step){
		bits_group.push(byte.substring(i, i + step))
	}
	return bits_group
}

function reverse_reshape(population){
	return population.join('')
}

/* --------------------------------------- --------------------------------------- --------------------------------------- */

/* --------------------------------------- DNA DECRYPT --------------------------------------- */

function DNA_decrypt(data, key){
	//generate encoding tables domains
	const two_bit_list = ['00', '01', '10', '11']
	const dna_bases = ['A', 'C', 'G', 'T']

	const four_bit_list = ['0000', '0001', '0010', '0011', '0100', '0101', '0110', '0111', '1000', '1001', '1010', '1011', '1100',
					 '1101', '1110', '1111']
	const two_dna_bases = ['TA', 'TC', 'TG', 'TT', 'GA', 'GC', 'GG', 'GT', 'CA', 'CC', 'CG', 'CT', 'AA', 'AC', 'AG', 'AT']
	//zip two_bit_list and dna_bases together
	two_bit_list.forEach((z, i) => two_bits_to_dna_base_table[z] = dna_bases[i])
	
	//Zip DNA base together
	dna_bases.forEach((z, i) => dna_base_to_two_bits_table [z] = two_bit_list[i])
	
	
	//Zip 4 bit list together with 2 DNA bases
	four_bit_list.forEach((z, i) => four_bits_to_two_dna_base_table [z] = two_dna_bases[i])
	
	//Zip 4 bit list together with 2 DNA bases
	two_dna_bases.forEach((z, i) => two_dna_base_to_four_bits_table [z] = four_bit_list[i])
	
	var rounds_no = parseInt(get_pattern(no_rounds_del, key)[0],10)
	const rounds = get_pattern(round_del, key) 
	
	var shuffledData = data
	var bData4;

	while(rounds_no > 0){
		var round_info = rounds[rounds_no - 1]
		//create the chromosome population
		
		const firstData = dreshape(shuffledData, get_pattern(reshape_del, round_info))
		//apply mutation on population
		const secondData = dmutation(firstData, get_pattern(mutation_del, round_info))
		//# apply crossover on population
		const thirdData = d_crossover(secondData, round_info)[0]
		
		const encryption_key = get_pattern(key_del, key)[0]
		const bData1 = dna_to_bits(thirdData, dna_base_to_two_bits_table)
		const bData2 = encrypt_key(bData1, encryption_key)
		const bData3 = group_bits(bData2)
		bData4 = bits_to_dna(bData3,two_bits_to_dna_base_table)
		
		rounds_no -= 1
	}
	console.log(dna_to_bits(bData4,dna_base_to_two_bits_table))
	//return binaryToString(dna_to_bits(bData4,dna_base_to_two_bits_table))
	
}

function d_crossover(population, crossover_info){
	const crossover_type = get_pattern(crossover_type_del, crossover_info)[0]
	
	if(crossover_type == "rotate_crossover"){
		var rotate_info = get_pattern(rotate_crossover_del, crossover_info)[0]
		return d_rotate_crossover(population, rotate_info)
	}
	else if(crossover_type == "single_point_crossover"){
		single_point_info = get_pattern(single_point_crossover_del, crossover_info)[0]
        return d_single_point_crossover(population, single_point_info)
	}else if (crossover_type == "both"){
		rotate_info = get_pattern(rotate_crossover_del, crossover_info)[0]
        single_point_info = get_pattern(single_point_crossover_del, crossover_info)[0]
        population = d_single_point_crossover(population, single_point_info)
        return d_rotate_crossover(population, rotate_info)
	}
}

function d_rotate_crossover(population, rotate_info){
	var new_population = []
	var rotation_offset = parseInt(get_pattern(rotation_offset_del, rotate_info)[0], 10)
	var rotations = get_pattern(rotation_types_del, rotate_info)[0].split("|")
	rotations.splice(-1,1)
	
	for(var i = 0; i < population.length; i++){
		var chromosome = population[i]
		var direction = rotations[i]
		
		if(direction == "left"){
			right_first = chromosome.substring(0,chromosome.length - rotation_offset)
            right_second = chromosome.substring(chromosome.length - rotation_offset, chromosome.length)
			new_population.push(right_second + right_first)
		}else if (direction == "right"){
			left_first = chromosome.substring(0, rotation_offset)
            left_second = chromosome.substring(rotation_offset, chromosome.length)
            new_population.push(left_second + left_first)
		}
	}
	return new_population
}

function d_single_point_crossover(population, single_point_info){
	var splitedSPI = single_point_info.split("|")
	var crossover_points = []
	
	for(var i in splitedSPI){
		if(splitedSPI[i]!=''){
			crossover_points.push(parseInt(splitedSPI[i],10))
		}
	}
	
	var new_population = []
	for(var i = 0; i < population.length - 1; i+=2){
		var candidate1 = population[i]
        var candidate2 = population[i + 1]
		
		var crossover_point = crossover_points[parseInt(i / 2, 10)]
		var offspring1 = candidate2.substring(0, crossover_point) + candidate1.substring(crossover_point, candidate1.length)
        var offspring2 = candidate1.substring(0, crossover_point) + candidate2.substring(crossover_point, candidate1.length)
        new_population.push(offspring1)
        new_population.push(offspring2)
	}
	
	if(population.length % 2 == 1){
		new_population.push(population[population.length - 1])
	}
	
	return new_population

}


function dmutation(population, mutation_info){
	const alter_dna_table = JSON.parse(get_pattern(mutation_table_del, mutation_info[0])[0])
	var chromosomes_info = get_pattern(chromosome_del, mutation_info[0])
	
	var new_population = []
	for(var i = 0; i < population.length; i++){
		var chromosome = population[i]
        chromosome_info = chromosomes_info[i]
		
		// # alter back the dna bases between point1 and point2
		var alter_info = get_pattern(alter_mutation_del, chromosome_info)[0]
		var parsedInfo = JSON.parse("[" + alter_info.replace(/\(/g, "[").replace(/\)/g, "]") + "]")[0]
		var point1 = parsedInfo[0]
		var point2 = parsedInfo[1]
		
		var new_chromosome = ""
		for (var z = 0; z < chromosome.length; z++){
			if(z>=point1 && z<= point2){
				new_chromosome += alter_dna_table[chromosome[z]]
			}else{
				new_chromosome += chromosome[z]
			}
		}
		var two_bases_vector = group_bits(new_chromosome)
		var last_two_bits = null
		if(new_chromosome.length % 2 == 1){
			last_two_bits = dna_base_to_two_bits_table[new_chromosome[-1]]
			two_bases_vector.splice(-1,1)
		}
		
		var bits_seq = d_dna_to_bits(two_bases_vector, two_dna_base_to_four_bits_table)
		
		if(last_two_bits != null){
			bits_seq += last_two_bits
		}
		
		var complement_info = get_pattern(complement_mutation_del, chromosome_info)[0]
		var pparsedInfo = JSON.parse("[" + complement_info.replace(/\(/g, "[").replace(/\)/g, "]") + "]")[0]
		var point3 = pparsedInfo[0]
		var point4 = pparsedInfo[1]
		
		var b_chromosome = complement(bits_seq, point3, point4)
		var bb_chromosome = group_bits(b_chromosome)
		new_chromosome = bits_to_dna(bb_chromosome, two_bits_to_dna_base_table)
		new_population.push(new_chromosome)
	}
	return new_population
}


function dreshape(dna_sequence, reshape_info){
	const chromosome_length = parseInt(reshape_info[0],10)
	var chromosomes = []
	for(var i = 0 ; i < dna_sequence.length; i+=chromosome_length){
		chromosomes.push(dna_sequence.substring(i, i + chromosome_length))
	}
	return chromosomes
}

function get_pattern(delimiter, s){
	//Get the pattern info between delimiters from the string
	const regex = delimiter + "(.*?)" + delimiter
	
	const test = Array.from(s.matchAll(regex), m => m[0]);
	
	for(var i in test){
		test[i] = test[i].split(delimiter).join('')
	}
	
	return test
}

function d_dna_to_bits(data, table){
	var temp = ''
	for(var i in data){
		temp += table[data[i]]
	}
	return temp
}
