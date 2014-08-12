
var openpgp = require('openpgp');

openpgp.crypto.random.getRandomValues = function(buf) {
  //console.log('Random values (' + buf.length + ')');
  var hex = jscore.getRandomHexString(buf.length);
  for (var i = 0; i < buf.length; i += 1) {
    var r = parseInt(hex.substr(i*2, 2), 16);
    buf[i] = r;
  }
};

var armor = openpgp.armor;
var util = openpgp.util;
var enums = openpgp.enums;
var cleartext = openpgp.cleartext;

jscore.encrypt = function(params) {
  var encryptFor = params["encrypt_for"],
    signWith = params["sign_with"],
    passphrase = params["passphrase"],    
    text = params["text"],
    success = params["success"],
    failure = params["failure"];

  var key = openpgp.key.readArmored(encryptFor).keys[0];
  if (!key) {
    failure("Couldn't decode public key");
    return;
  }
  var messageArmored = openpgp.encryptMessage(key, text);
  success(messageArmored);
};

jscore.decrypt = function(params) {
  var messageArmored = params["message_armored"],
    decryptWith = params["decrypt_with"],
    passphrase = params["passphrase"],
    success = params["success"],
    failure = params["failure"];

  var key = openpgp.key.readArmored(decryptWith).keys[0];
  if (!key) {
    failure("Couldn't decode private key");
    return;
  }
  if (!key.decrypt(passphrase)) {
    failure("Couldn't decrypt private key with password");
    return;
  }
  var message = openpgp.message.readArmored(messageArmored);
  var plainText = openpgp.decryptMessage(privkeyateKey, message);
  success(plainText);
};

jscore.sign = function(params) {
  var signWith = params["sign_with"],
    passphrase = params["passphrase"],
    text = params["text"],
    success = params["success"],
    failure = params["failure"];

  var key = openpgp.key.readArmored(signWith).keys[0];
  if (!key.decrypt(passphrase)) {
    failure("Failure to decrypt private key");
    return;
  }
  var messageArmored = openpgp.signClearMessage(key, text);
  success(messageArmored);
};

jscore.verify = function(params) {
  var messageArmored = params["message_armored"],
    verifyFor = params["verify_for"],
    success = params["success"],
    failure = params["failure"];

  var publicKeys = [];
  if (verifyFor) publicKeys = openpgp.key.readArmored(verifyFor).keys;

  var cleartextMessage = openpgp.cleartext.readArmored(clearTextArmored);
  var result = openpgp.verifyClearSignedMessage(publicKeys, cleartextMessage)
  var cleartextSigs = result.signatures;
  for (var i = 0; i < cleartextSigs.length; i++) {
    var cleartextSig = cleartextSigs[i];
    if (!cleartextSig.valid) return null;
  }
  return result.text;
};



jscore.armorPublicKey = function(params) {
  var data = params["data"],
    success = params["success"],
    failure = params["failure"];

  var bindata = util.hex2bin(data);
  success(armor.encode(enums.armor.public_key, bindata));
};

jscore.armorPrivateKey = function(params) {
  var data = params["data"],
    success = params["success"],
    failure = params["failure"];
  var bindata = util.hex2bin(data);
  success(armor.encode(enums.armor.private_key, bindata));
};

jscore.dearmor = function(params) {
  var armored = params["armored"],
    success = params["success"],
    failure = params["failure"];

  var result = armor.decode(armored);
  success(util.hexstrdump(result.data));
};

jscore._privateKeyPacket = function(key) {
  var keys = key.getAllKeyPackets();
  for (var i = 0; i < keys.length; i++) {
    if (keys[i].tag == enums.packet.secretKey || keys[i].tag == enums.packet.secretSubkey) return keys[i];
  }
  return null;
};

jscore.generateKeyPair = function(params) {
  var userid = params["userid"],
    passphrase = params["passphrase"],
    success = params["success"],
    failure = params["failure"];

  // Unlocked is important, otherwise the privateKey data is invalid
  var result = openpgp.generateKeyPair({numBits: numBits, userId: userid, passphrase: passphrase, unlocked: true});
  var key = result.key;
  var publicKeyArmored = result.publicKeyArmored;
  var privateKeyArmored = result.privateKeyArmored;
  var publicKeyHex = util.hexstrdump(armor.decode(publicKeyArmored).data);
  var privateKeyHex = util.hexstrdump(armor.decode(privateKeyArmored).data);
  var privateKeyId = jscore._privateKeyPacket(key).getKeyId().toHex();

  var publicKey = openpgp.key.readArmored(publicKeyArmored).keys[0];
  var publicKeyId = publicKey.getKeyIds()[0].toHex();

  success(publicKeyHex, privateKeyHex, publicKeyId);
};
