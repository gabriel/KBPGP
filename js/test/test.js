var assert = require("assert");

var fs = require("fs");
var vm = require("vm");

vm.runInThisContext(fs.readFileSync("./keybase.js"));
vm.runInThisContext(fs.readFileSync("./keybase-kbpgp-jscore.js"));

var dataDir = "../Tests/Data";

jscore.kbcrypto = {};
jscore.kbcrypto.keyfetch = function(hex_key_ids, ops, success, failure) {
  if (hex_key_ids[0] == "4bf812991a9c76ab" && (ops & 4) != 0) {    
    success(datafile("user2_public.asc"));
  } else {
    failure(new Error("No key for " + hex_key_ids + ", ops: " + ops));
  }
};

var crypto = require("crypto");
jscore.getRandomHexString = function(length) {
  return crypto.randomBytes(length).toString("hex");
};

var datafile = function(path) {
  return fs.readFileSync("../Tests/Data/" + path).toString();
};

var failure = function(msg) { throw new Error(msg); };

describe("JSCore", function() {
  this.timeout(10000);

  it("should decrypt with private key", function(done) {   
    jscore.decrypt({
      message_armored: datafile("user1_message_kb.asc"),
      decrypt_with: datafile("user1_private.asc"),
      passphrase: "toomanysecrets",
      success: function(plain_text, signers) {
        assert.equal(plain_text, "this is a test message to gabrielhlocal2");          
        done();
      },
      failure:failure
    });
  });  

  it("should decrypt with private key (gpg2)", function(done) {   
    jscore.decrypt({
      message_armored: datafile("user1_message_gpg2.asc"),
      decrypt_with: datafile("user1_private.asc"),
      passphrase: "toomanysecrets",
      success: function(plain_text, signers) {
        assert.equal(plain_text, "this is a test message to gabrielhlocal2");          
        done();
      },
      failure:failure
    });
  });  

  it("should encrypt/sign/decrypt/verify", function(done) {    
    // Encrypt and sign
    jscore.encrypt({
      encrypt_for: datafile("user1_public.asc"),
      sign_with: datafile("user2_private.asc"),
      passphrase: "toomanysecrets",
      text: "this is a secret message from user2 signed by user1",
      success: function(message_armored) {        

        // Decrypt and verify        
        jscore.decrypt({
          message_armored: message_armored,
          decrypt_with: datafile("user1_private.asc"),          
          passphrase: "toomanysecrets",        
          success: function(plain_text, signers) {
            assert.equal(plain_text, "this is a secret message from user2 signed by user1")
            assert.deepEqual(signers, ["664cf3d7151ed6e38aa051c54bf812991a9c76ab"]);
            done();
          },
          failure:failure
        });

      },
      failure:failure
    });
  });

  it("should decrypt with private key unlocked", function(done) {   
    jscore.decrypt({
      message_armored: datafile("user1_message_kb.asc"),
      decrypt_with: datafile("user1_private_unlocked.asc"),
      success: function(plain_text, signers) {
        assert.equal(plain_text, "this is a test message to gabrielhlocal2");          
        done();
      },
      failure:failure
    });
  });

  it("should generate key", function(done) {
    this.timeout(100000);
    jscore.generateKeyPair({
      userid: "keybase.io/testuser <testuser@keybase.io>",
      passphrase: "toomanysecrets",      
      success: function(public_key_hex, private_key_hex, key_fingerprint) {        
        done();
      },
      failure:failure
    })
  });

  it("should cancel generate key", function(done) {
    this.timeout(100000);
    jscore.generateKeyPair({
      userid: "keybase.io/testuser <testuser@keybase.io>",
      passphrase: "toomanysecrets",      
      progress: function(o) {
        return false;
      },
      success: function(public_key_hex, private_key_hex, key_fingerprint) {
        assert.ok(false, "should cancel");
      },
      failure: function(err) {        
        done();
      }
    })
  });

  // it("should be in keyring", function(done) {
  //   var decrypt_with = datafile("user1_private_unlocked.asc");
  //   kbpgp.KeyManager.import_from_armored_pgp({
  //     raw: decrypt_with
  //   }, function(err, key) {
      
  //     console.log("PGP locked: " + key.is_pgp_locked());      
  //     console.log("Has private: " + key.has_pgp_private());

  //     console.log("Fingerprint: " + key.get_pgp_fingerprint().toString("hex"));
      
  //     var exported = key.export_pgp_keys_to_keyring()
  //     console.log("Exporting: ")
  //     for (var i = 0; i < exported.length; i++) {
  //       var k = exported[i];
  //       console.log("  Key id: " + k.key_material.get_key_id().toString("hex"));
  //       console.log("  Flags: " + k.key_material.flags);
  //       console.log("  Has private: " + k.key.has_private());        
  //     }

  //     var keyring = new kbpgp.keyring.PgpKeyRing();
  //     keyring.add_key_manager(key);

  //     var key_id = new Buffer("D53374F55303D0EA", "hex");                  
  //     //"89AE977E1BC670E5"
  //     //"D53374F55303D0EA" 
      
  //     keyring.fetch([key_id], 0x2, function(err, k, i) {
  //       if (err) {
  //         console.log(err);
  //         throw err;
  //       } else {
  //         console.log("Key: " + key_id.toString("hex"));
  //         console.log("  Flags: " + k.key_material.flags);          
  //         console.log("  Key id: " + k.key_material.get_key_id().toString("hex"));          
  //         console.log("  Has private: " + k.key.has_private());
  //         console.log("  Can perform ops decrypt 0x2: " + k.key.can_perform(0x2));
  //         console.log("  Can perform ops verify 0x4: " + k.key.can_perform(0x4));
  //       }
  //       done();
  //     });
  //   });
  // });

  // it("should decrypt with p3skb bundle", function(done) {    
  //   jscore.decrypt({
  //     message_armored: datafile("user1_message_kb.asc"),
  //     decrypt_with: datafile("user1_private.p3skb"),
  //     passphrase: "toomanysecrets",
  //     success: function(plain_text, signers) {
  //       assert.equal(plain_text, "this is a test message to gabrielhlocal2");          
  //       done();
  //     },
  //     failure:failure
  //   });
  // });

});
