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
    failure(new Error("No key for " + hex_key_ids));
  }
};

var crypto = require("crypto");
jscore.getRandomHexString = function(length) {
  return crypto.randomBytes(length).toString("hex");
};

var datafile = function(path) {
  return fs.readFileSync("../Tests/Data/" + path).toString();
};

describe("JSCore", function() {
  
  // Only supporting decrypt_with for now
  // it("should decrypt", function(done) {   
  //   var params = {
  //     message_armored: datafile("user1_message_kb.asc"),
  //     success: function(plainText, signers) {
  //       assert.equal(plainText, "this is a test message to gabrielhlocal2");          
  //       done();
  //     },
  //     failure: function(err) {
  //       throw new Error(err);
  //     },
  //   };

  //   jscore.decrypt(params);
  // });

  it("should decrypt with private key", function(done) {   
    jscore.decrypt({
      message_armored: datafile("user1_message_kb.asc"),
      decrypt_with: datafile("user1_private.asc"),
      passphrase: "toomanysecrets",
      success: function(plain_text, signers) {
        assert.equal(plain_text, "this is a test message to gabrielhlocal2");          
        done();
      },
      failure: function(err) {
        throw new Error(err);
      },
    });
  });

  it("should encrypt/sign/decrypt/verify", function(done) {    
    this.timeout(10000);

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
          failure: function(err) {
            throw new Error(err);
          },
        });
      },
      failure: function(err) {
        throw new Error(err);
      },
    });
  });

});
