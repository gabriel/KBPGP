var assert = require("assert");

var fs = require("fs");
var vm = require("vm");

vm.runInThisContext(fs.readFileSync("./keybase.js"));
vm.runInThisContext(fs.readFileSync("./keybase-kbpgp-jscore.js"));

var dataDir = "../Tests/Data";

// jscore.kbcrypto = {};
// jscore.kbcrypto.keyfetch = function(hex_key_ids, ops, success, failure) {
//   if (hex_key_ids[0] == "4bf812991a9c76ab" && (ops & 4) != 0) {    
//     success(datafile("user2_public.asc"));
//   } else {
//     failure(new Error("No key for " + hex_key_ids + ", ops: " + ops));
//   }
// };

var crypto = require("crypto");
jscore.getRandomBase64String = function(length) {
  return crypto.randomBytes(length).toString("base64");
};

var datafile = function(path) {
  return fs.readFileSync("../Tests/Data/" + path).toString();
};

var failure = function(msg) { throw new Error(msg); };

describe("JSCore", function() {
  this.timeout(10000);

  var emptykeyring = new kbpgp.keyring.PgpKeyRing();

  var keyring = new kbpgp.keyring.PgpKeyRing();
  kbpgp.KeyManager.import_from_armored_pgp({raw: datafile("user2_public.asc")}, function(err, km) {
    keyring.add_key_manager(km);
  });

  it("should decrypt with private key kb", function(done) {   
    jscore.decrypt({
      message_armored: datafile("user1_message_kb.asc"),
      decrypt_with: datafile("user1_private.asc"),
      keyring: keyring,
      passphrase: "toomanysecrets",
      success: function(data, signers, warnings) {
        var plaintext = new Buffer(data, "base64").toString("utf8");
        assert.equal(plaintext, "this is a test message to gabrielhlocal2");          
        done();
      },
      failure:failure
    });
  });  

  it("should decrypt with private key gpg2", function(done) {   
    jscore.decrypt({
      message_armored: datafile("user1_message_gpg2.asc"),
      decrypt_with: datafile("user1_private.asc"),
      keyring: keyring,
      passphrase: "toomanysecrets",
      success: function(data, signers, warnings) {
        var plaintext = new Buffer(data, "base64").toString("utf8");
        assert.equal(plaintext, "this is a test message to gabrielhlocal2");          
        done();
      },
      failure:failure
    });
  });  

  it("should encrypt/sign/decrypt/verify", function(done) {    
    this.timeout(30000);
    // Encrypt and sign
    jscore.encrypt({
      encrypt_for: [datafile("user1_public.asc"), datafile("user2_public.asc")],
      sign_with: datafile("user2_private.asc"),
      passphrase: "toomanysecrets",
      text: "this is a secret message to user1 signed by user2",
      success: function(message_armored) {        

        // Decrypt for user1 and verify        
        jscore.decrypt({
          message_armored: message_armored,
          decrypt_with: datafile("user1_private.asc"),
          keyring: keyring,      
          passphrase: "toomanysecrets",        
          success: function(data, signers, warnings) {
            var plaintext = new Buffer(data, "base64").toString("utf8");
            assert.equal(plaintext, "this is a secret message to user1 signed by user2")
            assert.deepEqual(signers, ["664cf3d7151ed6e38aa051c54bf812991a9c76ab"]);            

            // Decrypt for user2
            jscore.decrypt({
              message_armored: message_armored,
              decrypt_with: datafile("user2_private.asc"),
              keyring: emptykeyring,      
              passphrase: "toomanysecrets",        
              success: function(data, signers, warnings) {
                var plaintext = new Buffer(data, "base64").toString("utf8");
                assert.equal(plaintext, "this is a secret message to user1 signed by user2")
                assert.deepEqual(signers, ["664cf3d7151ed6e38aa051c54bf812991a9c76ab"]);
                done();
              },
              failure:failure
            });
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
      keyring: keyring,
      success: function(data, signers, warnings) {
        var plaintext = new Buffer(data, "base64").toString("utf8");
        assert.equal(plaintext, "this is a test message to gabrielhlocal2");          
        done();
      },
      failure:failure
    });
  });

  it("should generate key", function(done) {
    this.timeout(100000);
    var userids = ["keybase.io/testuser <testuser@keybase.io>"];
    
    jscore.generateKeyPair({
      userids: userids,
      passphrase: "toomanysecrets",      
      success: function(public_key_data, private_key_data, key_fingerprint) {        
        done();
      },
      failure:failure
    })
  });

  it("should verify detached", function(done) {
    jscore.verify({
      armored: datafile("user2_sig.asc"),
      data: new Buffer("this is a test message to gabrielhlocal2\n", "utf8").toString("base64"),
      keyring: keyring,
      success: function(data, signers, warnings) {
        done();
      },
      failure:failure
    });
  });

  it("should verify detached fail", function(done) {
    jscore.verify({
      armored: datafile("user2_sig.asc"),
      data: new Buffer("not the right message", "utf8").toString("base64"),
      keyring: keyring,
      success: function(data, signers, warnings) {
        assert.ok(false, "should fail");
      },
      failure:function(err) {        
        done();
      }
    });
  });

  it("should cancel generate key", function(done) {
    this.timeout(100000);
    jscore.generateKeyPair({
      userids: ["keybase.io/testuser <testuser@keybase.io>"],
      passphrase: "toomanysecrets",      
      progress: function(o) {
        return false;
      },
      success: function(public_key_data, private_key_data, key_fingerprint) {
        assert.ok(false, "should cancel");
      },
      failure: function(err) {        
        done();
      }
    })
  });

  it("should get info for public key", function(done) {
    this.timeout(100000);
    var armored = datafile("user1_public.asc");
    jscore.info({
      armored: armored,
      success: function(info) {
        done();
      },
      failure:failure
    });
  });

  it("should get info for gpg key", function(done) {
    var armored = datafile("user2_private.asc");
    jscore.info({
      armored: armored,
      success: function(info) {
        done();
      },
      failure:failure
    });
  });

  it("should get info for ecc key", function(done) {
    var armored = datafile("user3_ecc_private.asc");
    jscore.info({
      armored: armored,
      success: function(info) {
        done();
      },
      failure:failure
    });
  });

  it("should set password", function(done) {
    var armored = datafile("user1_private.asc");
    jscore.setPassword({
      armored: armored,
      previous: "toomanysecrets",
      passphrase: "thisisanewpassword",
      success: function(armored2) {
        done();
      },
      failure:failure
    });
  });

  it("should clear password", function(done) {
    var armored = datafile("user1_private.asc");
    jscore.setPassword({
      armored: armored,
      previous: "toomanysecrets",
      passphrase: null,
      success: function(armored2) {
        jscore.checkPassword({
          armored: armored2,
          passphrase: null,
          success: function(success) {
            jscore.decrypt({
              message_armored: datafile("user1_message_kb.asc"),
              decrypt_with: armored2,
              keyring: keyring,
              success: function(data, signers, warnings) {
                done();
              },
              failure:failure
            });            
          },
          failure:failure
        });        
      },
      failure:failure
    });
  });

  it("should check password", function(done) {
    var armored = datafile("user4_private.asc");
    jscore.checkPassword({
      armored: armored,
      passphrase: "toomanysecrets",
      success: function() {
        done();
      },
      failure:failure
    });
  });

  it("should check password and fail", function(done) {
    var armored = datafile("user1_private.asc");
    jscore.checkPassword({
      armored: armored,
      passphrase: "badpassword",
      success: function(success) {
        assert.ok(!success, "should fail");
      },
      failure: function(err) {        
        done();
      }
    });    
  });

  it("should unbox gpg", function(done) {
    var unboxkeyring = new kbpgp.keyring.PgpKeyRing();
    jscore.decodeKey(datafile("user1_private.asc"), "toomanysecrets", function(err, km) {
      unboxkeyring.add_key_manager(km);      
    });
    jscore.decodeKey(datafile("user2_public.asc"), null, function(err, km2) {
      unboxkeyring.add_key_manager(km2);      
    });    

    jscore.unbox({
      message_armored: datafile("user1_message_gpgui.asc"),
      keyring: unboxkeyring,      
      success: function(data, signers, warnings) {
        var plaintext = new Buffer(data, "base64").toString("utf8");
        assert.equal(plaintext, "this is a signed test message");                  
        done();
      },
      failure:failure
    });
  });

  it("should unbox with warnings", function(done) {
    var unboxkeyring = new kbpgp.keyring.PgpKeyRing();
    jscore.decodeKey(datafile("user1_private.asc"), "toomanysecrets", function(err, km) {
      unboxkeyring.add_key_manager(km);
    });

    jscore.unbox({
      message_armored: datafile("user1_message_unk.asc"),
      keyring: unboxkeyring,      
      success: function(base64, signers, warnings) {
        var plaintext = new Buffer(data, "base64").toString("utf8");
        assert.equal(plaintext, "unknown signer (alice)");          
        console.log("warnings: " + jsondump(warnings));        
        done();
      },
      failure:failure
    });
  });

  it("should set userids", function(done) {
    var userids = ["Test User1 <test1@test.com>", "Test User2 <test2@test.com>", "Test User3 <test3@test.com>", 
      "Test User4 <test4@test.com>"];
    jscore.setUserIds({
      userids: userids,
      armored: datafile("user1_private.asc"),
      passphrase: "toomanysecrets",
      success: function(bundle) {
        // TODO
        done();
      },
      failure:failure
    });
  });

});
