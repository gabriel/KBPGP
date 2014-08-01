window = {}
window.crypto = {};
window.crypto.getRandomValues = function(buf) {
  //console.log("Random values (" + buf.length + ")");
  var hex = jscore.getRandomHexString(buf.length);
  for (var i = 0; i < buf.length; i += 1) {
    var r = parseInt(hex.substr(i*2, 2), 16);
    buf[i] = r;
  }
};

var kblog = function(obj) {
  seen = []
  if (obj === undefined) return "undefined";
  if (obj === null) return "null";

  var desc = JSON.stringify(obj, function(key, val) {
     if (val != null && typeof val == "object") {
          if (seen.indexOf(val) >= 0)
              return
          seen.push(val)
      }
      return val
  }, 2);

  console.log('\n' + obj.constructor.name + ': ' + desc);
};

var kbpgp = require("kbpgp");

//
// These methods are designed to be called from JavaScriptCore (ObjC) and
// are not meant to be idiomatic. How this code is written has a lot to
// do with how JSContent works.
//

// Encrypt
// text, encrypt_for, sign_with, passphrase, success, failure
jscore.encrypt = function(params) {
  var encrypt_for = params["encrypt_for"],
    sign_with = params["sign_with"],
    passphrase = params["passphrase"],    
    text = params["text"],
    success = params["success"],
    failure = params["failure"];

  jscore._decodeKeys(encrypt_for, sign_with, passphrase, function(public_key, private_key) {
    var kparams = {
      msg: text,
      encrypt_for: public_key
    };
    if (private_key) kparams["sign_with"] = private_key;
    kbpgp.burn(kparams, function(err, result_string, result_buffer) {
      success(result_string);
    });
  }, failure);
};

// Sign
// text, private_key_armored, passphrase, success, failure
jscore.sign = function(params) {
  var private_key_armored = params["private_key_armored"],
    passphrase = params["passphrase"],
    text = params["text"],
    success = params["success"],
    failure = params["failure"];

  jscore._decodePrivateKey(private_key_armored, passphrase, function(key) {
    var params = {
      msg: text,
      sign_with: key
    };

    kbpgp.burn(params, function(err, result_string, result_buffer) {
      if (err) { failure(err.message); return; }
      if (!result_string) { failure("No result string"); return; }
            
      success(result_string);
    });
  }, failure);
};

// Key fetch for decrypt/verify
jscore.keyfetch = {}
jscore.keyfetch.fetch = function(key_ids, ops, callback) {    
  var hex_key_ids = key_ids.map(function(k) { return k.toString("hex"); })
  jscore.kbcrypto.keyfetch(hex_key_ids, ops, function(bundle, username, passphrase) {
    kbpgp.KeyManager.import_from_armored_pgp({raw: bundle}, function(err, km) {

      if (passphrase && km.is_pgp_locked()) {
        km.unlock_pgp({
          passphrase: passphrase
        }, function(err) {
          if (err) { failure(err.message); return; }
        });
      }

      // Attach info to key, used to verify it later
      // in _process_literals.
      km.kbcrypto = {
        username: username
      };

      var keyring = new kbpgp.keyring.PgpKeyRing();
      keyring.add_key_manager(km);
      keyring.fetch(key_ids, ops, callback);
    });
  }, function(err_msg) {
    callback(new Error(err_msg));
  });
};

jscore.unbox = function(params) {
  var message_armored = params["message_armored"],
    success = params["success"],
    failure = params["failure"];

  var kparams = {
    armored: message_armored,
    keyfetch: jscore.keyfetch,
  };
  kbpgp.processor.do_message(kparams, function(err, literals) {
    if (err) { failure(err.message); return; }
    jscore._process_literals(literals, success);
  });
};
jscore.decrypt = jscore.unbox;
jscore.verify = jscore.unbox;

// Process literals from decrypt/verify
jscore._process_literals = function(literals, cb) {
  var text = literals[0].toString();
  var data_signers = literals[0].get_data_signers();      

  var signers = [];      
  for (var i = 0; i < data_signers.length; i++) {
    var data_signer = data_signers[i];
    var key = data_signer.sig.keyfetch_obj.km;
    var signer = {
      username: key.kbcrypto.username,
      key_id: key.get_pgp_key_id().toString("hex")
    };
    signers.push(signer);
  }  
  cb(text, signers);
};

jscore.generateKeyPair = function(params) {
  var nbits = params["nbits"],
    nbits_subkeys = params["nbits_subkeys"],
    userid = params["userid"],
    passphrase = params["passphrase"],
    success = params["success"],
    failure = params["failure"];

  var F = kbpgp["const"].openpgp;
  var opts = {
    userid: userid,
    primary: {
      nbits: nbits,
      flags: F.certify_keys | F.sign_data | F.auth | F.encrypt_comm | F.encrypt_storage,
      expire_in: 86400 * 365 * 5
    }, subkeys: [
    {
      nbits: nbits_subkeys,
      flags: F.sign_data,
      expire_in: 86400 * 365 * 2
    }, {
      nbits: nbits_subkeys,
      flags: F.encrypt_comm | F.encrypt_storage,
      expire_in: 86400 * 365 * 2
    }]
  };

  kbpgp.KeyManager.generate(opts, function(err, key) {
    if (err) { failure(err.message); return; }
    key.sign({}, function(err) {
      if (err) { failure(err.message); return; }
      key.export_pgp_private_to_client({
        passphrase: passphrase
      }, function(err, pgp_private) {
        if (err) { failure(err.message); return; }

        key.export_pgp_public({}, function(err, pgp_public) {
          if (err) { failure(err.message); return; }

          success(pgp_public, pgp_private, key.get_pgp_key_id().toString("hex"));
        });
      });
    });
  });
};

var armor = kbpgp.armor;

jscore.armorPublicKey = function(params) {
  var C = kbpgp["const"].openpgp;
  jscore._armor(C.message_types.public_key, params);
};

jscore.armorPrivateKey = function(params) {
  var C = kbpgp["const"].openpgp;
  jscore._armor(C.message_types.private_key, params);
};

jscore.dearmor = function(armored, success, failure) {
  var armored = params["armored"],
    success = params["success"],
    failure = params["failure"];
  var result = armor.decode(armored);
  var err = result[0], msg = result[1];
  if (err) {
    failure(err.message);
  } else {
    success(msg.body.toString("hex"));
  }
};

// ---

jscore._armor = function(message_type, params) {
  var data = params["data"],
    success = params["success"],
    failure = params["failure"];
  var buffer = new kbpgp.Buffer(data, "hex");
  var armored = armor.encode(message_type, buffer);
  if (armored) {
    success(armored);
  } else {
    failure("Unable to armor.encode");
  }
};

jscore._decodePublicKey = function(public_key_armored, success, failure) {
  kbpgp.KeyManager.import_from_armored_pgp({
    raw: public_key_armored
  }, function(err, key) {
    if (err) { failure(err.message); return; }
    success(key);
  });
};

jscore._decodePrivateKey = function(private_key_armored, passphrase, success, failure) {
  kbpgp.KeyManager.import_from_armored_pgp({
    raw: private_key_armored
  }, function(err, key) {
    if (err) { failure(err.message); return; }
    if (passphrase && key.is_pgp_locked()) {
      key.unlock_pgp({
        passphrase: passphrase
      }, function(err) {
        if (err) { failure(err.message); return; }
      });
    }
    success(key);
  });
};

jscore._decodeKeys = function(public_key_armored, private_key_armored, passphrase, success, failure) {
  jscore._decodePublicKey(public_key_armored, function(public_key) {
    if (!private_key_armored) {
      success(public_key, null);
      return;
    }
    jscore._decodePrivateKey(private_key_armored, passphrase, function(private_key) {
      success(public_key, private_key);
    }, failure);
  }, failure);
};



// jscore.decrypt = function(params) {
//   var message_armored = params["message_armored"],
//     private_key_armored = params["private_key_armored"],
//     passphrase = params["passphrase"],
//     success = params["success"],
//     failure = params["failure"];  
  
//   jscore._decodePrivateKey(private_key_armored, passphrase, function(private_key) {
//     var keyring = new kbpgp.keyring.PgpKeyRing();
//     keyring.add_key_manager(private_key);

//     var kparams = {
//       armored: message_armored,
//       keyfetch: keyring,
//     };
//     kbpgp.processor.do_message(kparams, function(err, literals) {            
//       if (err) { failure(err.message); return; }
//       jscore._process_literals(literals, success);
//     });    
//   }, failure);
// };
