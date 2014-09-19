#import <GRUnit/GRUnit.h>

#import "KBCrypto.h"

#import <GHKit/GHKit.h>

@interface KBCryptoTest : GRTestCase
@property KBCrypto *crypto;
@end

@implementation KBCryptoTest

- (void)tearDown {
  [_crypto clearContext];
  _crypto = nil;
}

- (NSString *)loadFile:(NSString *)file {
  NSString *path = [[NSBundle mainBundle] pathForResource:[file stringByDeletingPathExtension] ofType:[file pathExtension]];
  NSString *contents = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:NULL];
  NSAssert(contents, @"No contents at file: %@", file);
  return contents;
}

- (void)setUp:(dispatch_block_t)completion {
  if (_crypto) {
    completion();
    return;
  }
  _crypto = [[KBCrypto alloc] init];
  
  GHWeakSelf blockSelf = self;
  KBPGPKeyRing *keyRing = [[KBPGPKeyRing alloc] init];
  [_crypto setKeyRing:keyRing passwordBlock:nil];
  [_crypto PGPKeyForKeyBundle:[self loadFile:@"user1_public.asc"] keyBundlePassword:nil password:nil success:^(KBPGPKey *PGPKey1) {
    [keyRing addPGPKey:PGPKey1];
    
    [blockSelf.crypto PGPKeyForKeyBundle:[self loadFile:@"user2_public.asc"] keyBundlePassword:nil password:nil success:^(KBPGPKey *PGPKey2) {
      PGPKey2.verification = KBPGPVerificationManual;
      [keyRing addPGPKey:PGPKey2];
      
      completion();
      
    } failure:GRErrorHandler];
  } failure:GRErrorHandler];
}

- (void)testEncryptDecrypt:(dispatch_block_t)completion {
  GHWeakSelf blockSelf = self;
  [_crypto encryptText:@"This is a secret message" keyBundle:[self loadFile:@"user1_public.asc"] success:^(NSString *messageArmored) {
    [blockSelf.crypto decryptMessageArmored:messageArmored keyBundle:[self loadFile:@"user1_private.asc"] password:@"toomanysecrets" success:^(KBPGPMessage *message) {
      GRAssertEqualStrings(message.text, @"This is a secret message");
      
      completion();
    } failure:GRErrorHandler];
  } failure:GRErrorHandler];
}

- (void)testEncryptDecryptWithGPG:(dispatch_block_t)completion {
  GHWeakSelf blockSelf = self;
  [_crypto encryptText:@"This is a secret message" keyBundle:[self loadFile:@"user2_public.asc"] success:^(NSString *messageArmored) {
    [blockSelf.crypto decryptMessageArmored:messageArmored keyBundle:[self loadFile:@"user2_private.asc"] password:@"toomanysecrets" success:^(KBPGPMessage *message) {
      GRAssertEqualStrings(message.text, @"This is a secret message");
      completion();
    } failure:GRErrorHandler];
  } failure:GRErrorHandler];
}

//- (void)testSign:(dispatch_block_t)completion {
//  //GHWeakSelf blockSelf = self;
//  [_crypto signText:@"This is a secret message" keyBundle:[self loadFile:@"user1_private.asc"] password:@"toomanysecrets" success:^(NSString *armoredSignature) {
//    completion();
//  } failure:GRErrorHandler];
//}

- (void)testSignVerify:(dispatch_block_t)completion {
  GHWeakSelf blockSelf = self;
  [_crypto signText:@"This is a secret message" keyBundle:[self loadFile:@"user1_private.asc"] password:@"toomanysecrets" success:^(NSString *armoredSignature) {
    [blockSelf.crypto verifyMessageArmored:armoredSignature success:^(KBPGPMessage *message) {
      GRAssertEqualStrings(message.text, @"This is a secret message");
      completion();
    } failure:GRErrorHandler];
  } failure:GRErrorHandler];
}

- (void)testSignVerifyWithGPG:(dispatch_block_t)completion {
  GHWeakSelf blockSelf = self;
  [_crypto signText:@"This is a secret message" keyBundle:[self loadFile:@"user2_private.asc"] password:@"toomanysecrets" success:^(NSString *clearTextArmored) {
    [blockSelf.crypto verifyMessageArmored:clearTextArmored success:^(KBPGPMessage *message) {
      GRAssertEqualStrings(message.text, @"This is a secret message");
      completion();
    } failure:GRErrorHandler];
  } failure:GRErrorHandler];
}

- (void)testEncryptSignDecryptVerify:(dispatch_block_t)completion {
  GHWeakSelf blockSelf = self;
  [_crypto encryptText:@"This is a secret signed message" keyBundle:[self loadFile:@"user2_public.asc"] keyBundleForSign:[self loadFile:@"user1_private.asc"] passwordForSign:@"toomanysecrets" success:^(NSString *messageArmored) {
    [blockSelf.crypto decryptMessageArmored:messageArmored keyBundle:[self loadFile:@"user2_private.asc"] password:@"toomanysecrets" success:^(KBPGPMessage *message) {
      GRAssertEqualStrings(message.text, @"This is a secret signed message");
      GRAssertEqualStrings(@"afb10f6a5895f5b1d67851861296617a289d5c6b", [message.signers[0] PGPKey].fingerprint);
      completion();
    } failure:GRErrorHandler];
  } failure:GRErrorHandler];
}

- (void)testEncryptSignDecryptVerifyFromGPG:(dispatch_block_t)completion {
  GHWeakSelf blockSelf = self;
  [_crypto encryptText:@"This is a secret signed message" keyBundle:[self loadFile:@"user1_public.asc"] keyBundleForSign:[self loadFile:@"user2_private.asc"] passwordForSign:@"toomanysecrets" success:^(NSString *messageArmored) {
    [blockSelf.crypto decryptMessageArmored:messageArmored keyBundle:[self loadFile:@"user1_private.asc"] password:@"toomanysecrets" success:^(KBPGPMessage *message) {
      GRAssertEqualStrings(message.text, @"This is a secret signed message");
      GRAssertEqualObjects(@"664cf3d7151ed6e38aa051c54bf812991a9c76ab", [message.signers[0] PGPKey].fingerprint);
      completion();
    } failure:GRErrorHandler];
  } failure:GRErrorHandler];
}

- (void)testDecrypt:(dispatch_block_t)completion {
  NSArray *files = @[@"user1_message_kb.asc", @"user1_message_gpg1.asc", @"user1_message_gpg2.asc"];
  __block NSInteger index = 0;
  for (NSString *file in files) {
    GRTestLog(@"Testing file: %@", file);
    NSString *messageArmored = [self loadFile:file];
    [_crypto decryptMessageArmored:messageArmored keyBundle:[self loadFile:@"user1_private.asc"] password:@"toomanysecrets" success:^(KBPGPMessage *message) {
      GHDebug(@"Decrypted: %@", file);
      GRAssertEqualStrings(message.text, @"this is a test message to gabrielhlocal2");
   
      if (++index == [files count]) completion();
    } failure:GRErrorHandler];
  }
}

- (void)testDecryptWithP3SKB:(dispatch_block_t)completion {
  [_crypto decryptMessageArmored:[self loadFile:@"user1_message_kb.asc"] keyBundle:[self loadFile:@"user1_private.p3skb"] password:@"toomanysecrets" success:^(KBPGPMessage *message) {
    GRAssertEqualStrings(message.text, @"this is a test message to gabrielhlocal2");
    completion();
  } failure:GRErrorHandler];
}

- (void)testDecryptSignedMultipleRecipients:(dispatch_block_t)completion {
  NSArray *recipients = @[@"user1_private.asc", @"user2_private.asc"];
  __block NSInteger index = 0;
  for (NSString *recipient in recipients) {
    // user1_message_gpgui.asc is encrypted for user1 and user2 and signed by user2, using the gpg services encrypt gui
    [_crypto decryptMessageArmored:[self loadFile:@"user1_message_gpgui.asc"] keyBundle:[self loadFile:recipient] password:@"toomanysecrets" success:^(KBPGPMessage *message) {
      GRAssertEqualStrings(message.text, @"this is a signed test message");
      GRAssertEqualObjects(@"664cf3d7151ed6e38aa051c54bf812991a9c76ab", [message.signers[0] PGPKey].fingerprint);
      if (++index == [recipients count]) completion();
    } failure:GRErrorHandler];
  }
}

- (void)testVerify:(dispatch_block_t)completion {
  NSDictionary *files = @{
                     @"user1_clearsign_kb.asc": @"this is a signed message from gabrielhlocal2",
                     @"user1_clearsign_gpg1.asc": @"this is a signed message from gabrielhlocal2",
                     @"user1_sign_gpg1.asc": @"this is a signed message from gabrielhlocal2",
                     @"user1_sign_gpg2.asc": @"this is a signed message from gabrielhlocal2",
                     @"user2_clearsign_gpg2.asc": @"this is a signed message from gabrielhgpg2"};
  
  __block NSInteger index = 0;
  for (NSString *file in files) {
    NSString *messageArmored = [self loadFile:file];
    [_crypto verifyMessageArmored:messageArmored success:^(KBPGPMessage *message) {
      GHDebug(@"Verified: %@, %@", file, message.text);
      NSString *expected = files[file];
      GRAssertEqualStrings(expected, message.text);

      if (++index == [files count]) completion();
    } failure:GRErrorHandler];
  }
}

- (void)testVerifyFailure:(dispatch_block_t)completion {
  NSString *messageArmored = [self loadFile:@"user1_clearsign_fail.asc"];
  
  [_crypto verifyMessageArmored:messageArmored success:^(KBPGPMessage *message) {
    //GRFail(@"Should fail");
    [NSException raise:@"Fail" format:@"Should fail"];
  } failure:^(NSError *error) {
    GRTestLog(@"Failed ok: %@", error);
    completion();
  }];
}

- (void)testGenerateKeyRSA:(dispatch_block_t)completion {
  GHWeakSelf blockSelf = self;
  [_crypto generateKeyWithUserName:@"keybase.io/crypto" userEmail:@"user@email.com" keyAlgorithm:KBKeyAlgorithmRSA password:@"Setec Astronomy" progress:^BOOL(KBKeyGenProgress *progress) {
    GRTestLog(@"Progress: %@", [progress progressDescription]);
    return (!self.isCancelling);
  } success:^(P3SKB *secretKey, NSString *publicKeyArmored, NSString *keyFingerprint) {
    GRAssertNotNil([secretKey decryptPrivateKeyWithPassword:@"Setec Astronomy" error:nil]);
    
    GRTestLog(@"%@", publicKeyArmored);
    
    NSString *keyBundleAsP3SKB = [[secretKey data] base64EncodedStringWithOptions:0];
    NSString *text = @"Hi, my name is Werner Brandes. My voice is my passport. Verify Me.";
    
    [blockSelf.crypto encryptText:text keyBundle:publicKeyArmored keyBundleForSign:keyBundleAsP3SKB passwordForSign:@"Setec Astronomy" success:^(NSString *messageArmored) {
      [blockSelf.crypto decryptMessageArmored:messageArmored keyBundle:keyBundleAsP3SKB password:@"Setec Astronomy" success:^(KBPGPMessage *message) {
        GRAssertEqualStrings(text, message.text);
        completion();
      } failure:GRErrorHandler];
    } failure:GRErrorHandler];
  } failure:GRErrorHandler];
}

- (void)testGenerateKeyECC:(dispatch_block_t)completion {
  NSString *password = @"Setec Astronomy";
  GHWeakSelf blockSelf = self;
  [_crypto generateKeyWithUserName:@"keybase.io/crypto" userEmail:@"user@email.com" keyAlgorithm:KBKeyAlgorithmECDSA password:password progress:^BOOL(KBKeyGenProgress *progress) {
    GRTestLog(@"Progress: %@", [progress progressDescription]);
    return (!self.isCancelling);
  } success:^(P3SKB *secretKey, NSString *publicKeyArmored, NSString *keyFingerprint) {
    GRAssertNotNil([secretKey decryptPrivateKeyWithPassword:password error:nil]);
    
    //GRTestLog(@"%@", publicKeyArmored);
    
//    [blockSelf.crypto armoredKeyBundleFromSecretKey:secretKey previousPassword:password password:password success:^(NSString *privateKeyArmored) {
//      GRTestLog(privateKeyArmored);
//    } failure:GRErrorHandler];
    
    NSString *keyBundleAsP3SKB = [[secretKey data] base64EncodedStringWithOptions:0];
    NSString *text = @"Hi, my name is Werner Brandes. My voice is my passport. Verify Me.";
    
    [blockSelf.crypto encryptText:text keyBundle:publicKeyArmored keyBundleForSign:keyBundleAsP3SKB passwordForSign:@"Setec Astronomy" success:^(NSString *messageArmored) {
      [blockSelf.crypto decryptMessageArmored:messageArmored keyBundle:keyBundleAsP3SKB password:@"Setec Astronomy" success:^(KBPGPMessage *message) {
        GRAssertEqualStrings(text, message.text);
        completion();
      } failure:GRErrorHandler];
    } failure:GRErrorHandler];
  } failure:GRErrorHandler];
}

- (void)testGenerateKeyCancel:(dispatch_block_t)completion {
  __block NSInteger iter = 0;
  [_crypto generateKeyWithUserName:@"keybase.io/crypto" userEmail:@"user@email.com" keyAlgorithm:KBKeyAlgorithmRSA password:@"toomanysecrets" progress:^BOOL(KBKeyGenProgress *progress) {
    return (iter++ < 10);
  } success:^(P3SKB *privateKey, NSString *publicKeyArmored, NSString *keyFingerprint) {
    //GRFail(@"Should have cancelled");
    [NSException raise:@"Fail" format:@"Should fail"];
  } failure:^(NSError *error) {
    GRTestLog(@"Failed ok: %@", error);
    GRAssertEquals(error.code, KBCryptoErrorCodeCancelled);
    completion();
  }];
}

- (void)testDearmorArmorPrivate:(dispatch_block_t)completion {
  NSString *privateKeyArmored = [self loadFile:@"user1_private.asc"];
  
  GHWeakSelf blockSelf = self;
  [_crypto dearmor:privateKeyArmored success:^(NSData *privateKeyData) {
    P3SKB *secretKey = [P3SKB P3SKBWithPrivateKey:privateKeyData password:@"toomanysecrets" publicKey:nil error:nil];
    GRAssertNotNil(secretKey);
    [blockSelf.crypto armoredKeyBundleFromSecretKey:secretKey password:@"toomanysecrets" keyBundlePassword:@"toomanysecrets" success:^(NSString *privateKeyRearmored) {
//      NSString *key1 = [privateKeyArmored gh_lastSplitWithString:@"\n\n" options:0];
//      NSString *key2 = [privateKeyRearmored gh_lastSplitWithString:@"\n\n" options:0];
//      GRAssertEqualStrings(key1, key2);
      GRTestLog(privateKeyRearmored);
      completion();
    } failure:GRErrorHandler];
  } failure:GRErrorHandler];
}

- (void)testDearmorArmorPublic:(dispatch_block_t)completion {
  NSString *publicKeyArmored = [self loadFile:@"user1_public.asc"];
  GHWeakSelf blockSelf = self;
  [_crypto dearmor:publicKeyArmored success:^(NSData *publicKeyData) {
    [blockSelf.crypto armoredKeyBundleFromPublicKey:publicKeyData success:^(NSString *publicKeyRearmored) {
      NSString *key1 = [publicKeyArmored gh_lastSplitWithString:@"\n\n" options:0];
      NSString *key2 = [publicKeyRearmored gh_lastSplitWithString:@"\n\n" options:0];
      GRAssertEqualStrings(key1, key2);
      
      completion();
    } failure:GRErrorHandler];
  } failure:GRErrorHandler];
}

- (void)testPGPKeyFromPublicArmored:(dispatch_block_t)completion {
  NSString *bundle = [self loadFile:@"user1_public.asc"];
  GHWeakSelf blockSelf = self;
  [_crypto PGPKeyForKeyBundle:bundle keyBundlePassword:nil password:nil success:^(KBPGPKey *key) {
    GRAssertNotNil(key);
    GRTestLog(@"key: %@", key);
    
    [blockSelf.crypto armoredKeyBundleFromPGPKey:key password:nil keyBundlePassword:nil success:^(NSString *encoded) {
      GRTestLog(@"%@", encoded);
      completion();
    } failure:GRErrorHandler];
  } failure:GRErrorHandler];
}

- (void)testPGPKeyFromPrivateArmored:(dispatch_block_t)completion {
  NSString *bundle = [self loadFile:@"user1_private.asc"];
  [_crypto PGPKeyForKeyBundle:bundle keyBundlePassword:@"toomanysecrets" password:@"toomanysecrets" success:^(KBPGPKey *PGPKey) {
    GRAssertNotNil(PGPKey.secretKey);
    GRAssertTrue([PGPKey.publicKeyBundle gh_startsWith:@"-----BEGIN PGP PUBLIC KEY"]);
    
    NSError *error = nil;
    NSData *decrypted = [PGPKey.secretKey decryptPrivateKeyWithPassword:@"toomanysecrets" error:&error];
    GRAssertNil(error);
    GRAssertNotNil(decrypted);
    
    completion();
  } failure:GRErrorHandler];
}

- (void)testSetPasswordWithBadPrevious:(dispatch_block_t)completion {
  NSString *bundle = [self loadFile:@"user1_private.asc"];
  [_crypto setPasswordForArmoredKeyBundle:bundle previousPassword:@"badpassword" password:nil success:^(NSString *keyBundleNoPassword) {
    [NSException raise:@"Fail" format:@"Should fail"];
  } failure:^(NSError *error) {
    completion();
  }];
}

- (void)testSetPasswordWithBadEmptyPrevious:(dispatch_block_t)completion {
  NSString *bundle = [self loadFile:@"user1_private.asc"];
  [_crypto setPasswordForArmoredKeyBundle:bundle previousPassword:nil password:nil success:^(NSString *keyBundleNoPassword) {
    //GRFail(@"Should fail");
    [NSException raise:@"Fail" format:@"Should fail"];
  } failure:^(NSError *error) {
    completion();
  }];
}

- (void)testPGPKeyFromP3SKB:(dispatch_block_t)completion {
  P3SKB *secretKey = [P3SKB P3SKBFromKeyBundle:[self loadFile:@"user1_private.p3skb"] error:nil];
  GHWeakSelf blockSelf = self;
  [_crypto PGPKeyForSecretKey:secretKey success:^(KBPGPKey *PGPKey) {
    GRTestLog(@"key: %@", PGPKey);
    GRAssertNotNil(PGPKey.secretKey);
    GRAssertTrue([PGPKey.publicKeyBundle gh_startsWith:@"-----BEGIN PGP PUBLIC KEY"]);
    
    [blockSelf.crypto armoredKeyBundleFromPGPKey:PGPKey password:@"toomanysecrets" keyBundlePassword:@"toomanysecrets" success:^(NSString *encoded) {
      GRAssertNotNil(encoded);
      GRTestLog(@"%@", encoded);
      completion();
    } failure:GRErrorHandler];
  } failure:GRErrorHandler];
}

- (void)testArmorPublicKeyFromPGPKey:(dispatch_block_t)completion {
  P3SKB *secretKey = [P3SKB P3SKBFromKeyBundle:[self loadFile:@"user1_private.p3skb"] error:nil];
  [_crypto PGPKeyForSecretKey:secretKey success:^(KBPGPKey *PGPKey) {
    GRTestLog(PGPKey.publicKeyBundle);
    GRAssertTrue([PGPKey.publicKeyBundle gh_startsWith:@"-----BEGIN PGP PUBLIC KEY"]);
    completion();
  } failure:GRErrorHandler];
}

@end
