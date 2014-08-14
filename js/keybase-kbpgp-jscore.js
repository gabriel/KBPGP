window = {};
window.crypto = {};
window.crypto.getRandomValues = function(buf) {  
  var hex = jscore.getRandomHexString(buf.length);
  //console.log("Random values (" + buf.length + "): " + hex);
  for (var i = 0; i < buf.length; i += 1) {
    var r = parseInt(hex.substr(i*2, 2), 16);
    buf[i] = r;
  }
};

var kblog = function(obj) {
  seen = [];
  if (obj === undefined) return "undefined";
  if (obj === null) return "null";

  var desc = JSON.stringify(obj, function(key, val) {
     if (val !== null && typeof val == "object") {
          if (seen.indexOf(val) >= 0)
              return;
          seen.push(val);
      }
      if (val && val.type == "Buffer") {
        var buf = new Buffer(val.data);
        return "<Buffer:0x" + buf.toString("hex") + ">";
      }      
      return val;
  }, 2);

  console.log('\n' + obj.constructor.name + ': ' + desc);
};

var kberr = function(err) {
  return err.fileName + ":" + err.lineNumber + ", " + err.message;
};

var failure = function() {
  return err.message;
};

function ErrorHandler(failure) {
  this.failure = failure;
}
ErrorHandler.prototype.handle = function(err) {  
  this.failure(err.message);
};

var kbpgp = require("kbpgp");

//
// These methods are designed to be called from JavaScriptCore (ObjC) and
// are not meant to be idiomatic. How this code is written has a lot to
// do with how JSContent works.
//

var jscore = jscore || {};

jscore.encrypt = function(params) {
  var encrypt_for = params.encrypt_for,
    sign_with = params.sign_with,
    passphrase = params.passphrase,    
    text = params.text,
    success = params.success,
    failure = new ErrorHandler(params.failure);

  jscore._decodeKeys(encrypt_for, sign_with, passphrase, function(public_key, private_key) {
    var kparams = {
      msg: text,
      encrypt_for: public_key
    };
    if (private_key) kparams.sign_with = private_key;
    kbpgp.box(kparams, function(err, result_string, result_buffer) {
      success(result_string);
    });
  }, failure);
};

jscore.sign = function(params) {
  var sign_with = params.sign_with,
    passphrase = params.passphrase,
    text = params.text,
    success = params.success,
    failure = new ErrorHandler(params.failure);

  jscore._decodeKey(sign_with, passphrase, function(key) {
    var params = {
      msg: text,
      sign_with: key
    };

    kbpgp.box(params, function(err, result_string, result_buffer) {
      if (err) { failure.handle(err); return; }
      if (!result_string) { failure.handle(new Error("No result string")); return; }

      success(result_string);
    });
  }, failure);
};

function RemoteKeyFetch(keyring) {
  this.keyring = keyring;
}

RemoteKeyFetch.prototype.fetchRemote = function(key_ids, ops, callback) {
  var keyring = this.keyring;
  var hexkeyids = key_ids.map(function(k) { return k.toString("hex"); });
  jscore.kbcrypto.keyfetch(hexkeyids, ops, function(bundle) { //, passphrase) {
    kbpgp.KeyManager.import_from_armored_pgp({raw: bundle}, function(err, km) {
      if (err) { callback(err); return; }

      // if (passphrase && km.is_pgp_locked()) {
      //   km.unlock_pgp({
      //     passphrase: passphrase
      //   }, function(err) {
      //     if (err) { callback(err); return; }
      //   });
      // }

      //var keyring = new kbpgp.keyring.PgpKeyRing();
      keyring.add_key_manager(km);
      keyring.fetch(key_ids, ops, callback);
    });
  }, function(err_msg) {
    callback(new Error(err_msg));
  });
};

// Check local keyring and then fetch remote if not found
RemoteKeyFetch.prototype.fetch = function(key_ids, ops, callback) {  
  var fetcher = this;
  this.keyring.fetch(key_ids, ops, function(err, key, index) {
    if (err) {
      fetcher.fetchRemote(key_ids, ops, callback);
    } else {
      callback(err, key, index);
    }
  });
};

jscore.unbox = function(params) {
  var message_armored = params.message_armored,
    success = params.success,
    failure = new ErrorHandler(params.failure);

  var keyring = new kbpgp.keyring.PgpKeyRing();
  var kparams = {
    armored: message_armored,
    keyfetch: new RemoteKeyFetch(keyring),
  };
  kbpgp.unbox(kparams, function(err, literals) {
    if (err) { failure.handle(err); return; }
    jscore._process_literals(literals, success);
  });
};
jscore.verify = jscore.unbox;
//jscore.decrypt = jscore.unbox;

jscore.decrypt = function(params) {
  var message_armored = params.message_armored,
    decrypt_with = params.decrypt_with,
    passphrase = params.passphrase,
    success = params.success,
    failure = new ErrorHandler(params.failure);


  if (!decrypt_with) {
    //jscore.unbox(params);
    failure.handle(new Error("Must specify decrypt_with"));
    return;
  }

  jscore._decodeKey(decrypt_with, passphrase, function(private_key) {
    var keyring = new kbpgp.keyring.PgpKeyRing();
    keyring.add_key_manager(private_key);

    var kparams = {
      armored: message_armored,
      keyfetch: new RemoteKeyFetch(keyring),
    };
    kbpgp.unbox(kparams, function(err, literals) {
      if (err) { failure.handle(err); return; }
      jscore._process_literals(literals, success);
    });    
  }, failure);
};

// Process literals from decrypt/verify
jscore._process_literals = function(literals, cb) {
  var text = literals[0].toString();
  var data_signers = literals[0].get_data_signers();      

  var signers = [];      
  for (var i = 0; i < data_signers.length; i++) {
    var data_signer = data_signers[i];    
    var key = data_signer.sig.key_manager;
    if (key) {
      signers.push(key.get_pgp_fingerprint().toString("hex"));
    }
  }
  cb(text, signers);
};

jscore.generateKeyPair = function(params) {
  var userid = params.userid,
    passphrase = params.passphrase,
    progress = params.progress,
    algorithm = params.algorithm,
    success = params.success,
    failure = new ErrorHandler(params.failure);

  var opts = { 
    userid: userid,
  };

  if (progress) {
    opts.asp = new kbpgp.ASP({
      progress_hook: function(o) {
        var ok = true;
        if (o.what == "fermat" && o.section == "p") {
          ok = progress({
            type: "find_prime_p",
            prime: o.p.toString(),
            amount: -1
          });
        } else if (o.what == "fermat" && o.section == "q") {
          ok = progress({
            type: "find_prime_q",
            prime: o.p.toString(),
            amount: -1
          });
        } else if (o.what == "mr") {
          ok = progress({
            type: "testing",
            prime: o.p.toString(),
            amount: o.i / o.total
          });
        } else {
          //console.log("what: " + o.what);
        }
        if (!ok) {
          this.canceler().cancel();
        }
      }
    });  
  }

  var generate;
  if (algorithm == "ecc") {
    generate = kbpgp.KeyManager.generate_ecc;
  } else if (algorithm == "rsa") {
    generate = kbpgp.KeyManager.generate_rsa;
  } else {
    generate = kbpgp.KeyManager.generate_rsa;
  }

  generate(opts, function(err, key) {    
    if (err) { failure.handle(err); return; }
    key.sign({}, function(err) {
      if (err) { failure.handle(err); return; }
      key.export_pgp_private_to_client({
        passphrase: passphrase
      }, function(err, pgp_private) {
        if (err) { failure.handle(err); return; }

        key.export_pgp_public({}, function(err, pgp_public) {
          if (err) { failure.handle(err); return; }

          var pgp_public_hex = armor.decode(pgp_public);
          if (pgp_public_hex[0]) { failure.handle(pgp_public_hex[0]); return; }
          var pgp_private_hex = armor.decode(pgp_private);
          if (pgp_private_hex[0]) { failure.handle(pgp_private_hex[0]); return; }

          success(pgp_public_hex[1].body.toString("hex"), pgp_private_hex[1].body.toString("hex"), 
            key.get_pgp_fingerprint().toString("hex"));
        });
      });
    });
  });
};

var armor = kbpgp.armor;

jscore.armorPublicKey = function(params) {
  var data = params.data,
    success = params.success,
    failure = new ErrorHandler(params.failure);

  var C = kbpgp["const"].openpgp;
  var buffer = new kbpgp.Buffer(data, "hex");
  var armored = armor.encode(C.message_types.public_key, buffer);
  if (armored) {
    success(armored);
  } else {
    failure.handle(new Error("Unable to armor.encode"));
  }
};

jscore.armorPrivateKey = function(params) {
  var data = params.data,
    passphrase = params.passphrase,
    success = params.success,
    failure = new ErrorHandler(params.failure);

  var C = kbpgp["const"].openpgp;
  var buffer = new kbpgp.Buffer(data, "hex");
  var armored = armor.encode(C.message_types.private_key, buffer);
  if (armored) {
    jscore._decodeKey(armored, null, function(key) {
      key.sign({}, function(err) {
        if (err) { failure.handle(err); return; }
        key.export_pgp_private_to_client({
          passphrase: passphrase,
        }, function(err, armored) {
          if (err) { failure.handle(err); return; }
          success(armored);
        });
      });
    }, failure);
  } else {
    failure.handle(new Error("Unable to armor"));
  }
};

jscore.dearmor = function(params) {
  var armored = params.armored,
    success = params.success,
    failure = new ErrorHandler(params.failure);
  var result = armor.decode(armored);
  var err = result[0], msg = result[1];
  if (err) {
    failure.handle(err);
  } else {
    success(msg.body.toString("hex"));
  }
};

jscore._decodeKey = function(bundle, passphrase, success, failure) {
  kbpgp.KeyManager.import_from_armored_pgp({
    raw: bundle
  }, function(err, key) {
    if (err) { failure.handle(err); return; }

    if (passphrase && key.is_pgp_locked()) {
      key.unlock_pgp({
        passphrase: passphrase
      }, function(err) {
        if (err) { failure.handle(err); return; }
      });
    } else {
      // Workaround bug where you need to call unlock on unlocked key, will be fixed soon.
      key.unlock_pgp({}, function(err) {});
    }
    
    success(key);
  });
};

jscore._decodeKeys = function(public_key_bundle, private_key_bundle, passphrase, success, failure) {
  jscore._decodeKey(public_key_bundle, null, function(public_key) {
    if (!private_key_bundle) {
      success(public_key, null);
      return;
    }
    jscore._decodeKey(private_key_bundle, passphrase, function(private_key) {
      success(public_key, private_key);
    }, failure);
  }, failure);
};

jscore.keyInfo = function(params) {
  var armored = params.armored,
    passphrase = params.passphrase,
    success = params.success,
    failure = new ErrorHandler(params.failure);

  jscore._decodeKey(armored, passphrase, function(key) {

    var info = {};
    info.id = key.get_pgp_key_id().toString("hex");
    info.short_id = key.get_pgp_short_key_id().toString("hex");
    info.fingerprint = key.get_pgp_fingerprint().toString("hex");
    
    // KeyManager -> PgpEngine -> KeyWrapper (Primary/Subkey) -> Pair (KeyMaterial) -> Pub/Priv

    var lifespan = key.lifespan;     

    var keymat = key.get_all_pgp_key_materials(); 

    var primary = key.primary; // KeyWrapper (Primary/Subkey);  .key is Pair
    var pkeymat = keymat[0][0];

    // RSA:1, ECDSA:19

    info.primary = {
      id: pkeymat.get_key_id().toString("hex"),
      flags: pkeymat.flags,      
      type: primary.key.type, 
      timestamp: pkeymat.timestamp,
      is_locked: pkeymat.is_locked(),
      has_private: pkeymat.has_private() ? true : false,
      self_signed: pkeymat.is_self_signed(),        
    };

    if (primary.key.pub.nbits) info.primary.nbits = primary.key.pub.nbits();

    // userids: pkeymat.get_signed_userids()[0].userid.toString("utf8")

    info.subkeys = [];

    var subkeys = key.subkeys;
    for (var i = 0; i < subkeys.length; i++) {
      var subkeymat = keymat[i+1][0];
      var subinfo = {
        id: subkeymat.get_key_id().toString("hex"),
        flags: subkeymat.flags,
        timestamp: subkeymat.timestamp,
      };

      if (subkeys[i].key.pub.nbits) subinfo.nbits = subkeys[i].key.pub.nbits();

      info.subkeys.push(subinfo);
    }      

    info.userids = [];
    var userids = key.get_userids_mark_primary();
    for (var i = 0; i < userids.length; i++) {
      info.userids.push({
        is_primary: userids[i].primary,
        username: userids[i].get_username(),
        email: userids[i].get_email(),
        comment: userids[i].get_comment(),
        //most_recent_sig: userids[i].most_recent_sig,
      });
    }

    success(info);      
  }, failure);
};


//Export
// key.sign({}, function(err) {
//   key.export_pgp_private_to_client({}, function(err, msg) {
//     console.log(err);
//     console.log(msg);        
//   });
// });


// jscore._decodeP3SKBKey = function(bundle, passphrase, success, failure) {
//   kbpgp.KeyManager.import_from_p3skb({
//     raw: bundle
//   }, function(err, key) {
//     if (err) { failure.handle(err); return; }
//     if (passphrase && key.is_p3skb_locked()) {
//       var tsenc = new kbpgp.Encryptor({
//         key: kbpgp.util.bufferify(passphrase),
//         version: 3
//       });
//       key.unlock_p3skb({
//         tsenc: tsenc        
//       }, function(err) {
//         if (err) { failure.handle(err); return; }
//       });
//     }
//     success(key);
//   });
// };
