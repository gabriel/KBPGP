#import <GRUnit/GRUnit.h>

@interface KBCryptoTest : GRTestCase
@end

#import "KBCrypto.h"
#import "KBTestKeyRing.h"
#import "KBSigner.h"

#import <GHKit/GHKit.h>

#define TEST_PASSWORD (@"toomanysecrets")

@implementation KBCryptoTest

- (NSData *)loadBase64Data:(NSString *)file {
  NSString *path = [[NSBundle mainBundle] pathForResource:[file stringByDeletingPathExtension] ofType:[file pathExtension]];
  return [[NSData alloc] initWithBase64EncodedData:[[NSData alloc] initWithContentsOfFile:path] options:0];
}

- (NSString *)loadFile:(NSString *)file {
  NSString *path = [[NSBundle mainBundle] pathForResource:[file stringByDeletingPathExtension] ofType:[file pathExtension]];
  NSString *contents = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:NULL];
  NSAssert(contents, @"No contents at file: %@", file);
  return contents;
}

- (id<KBKeyRing>)keyRing {
  KBTestKeyRing *keyRing = [[KBTestKeyRing alloc] init];
  
  [keyRing addVerifiedKeyFingerprint:@"afb10f6a5895f5b1d67851861296617a289d5c6b"];
  
  KBKeyBundle *publicKey1 = [[KBKeyBundle alloc] initWithBundle:[self loadFile:@"user1_public.asc"] userName:@"gabrielhlocal2" fingerprint:@"afb10f6a5895f5b1d67851861296617a289d5c6b" secret:NO];
  [keyRing addKey:publicKey1 PGPKeyIds:@[@"89ae977e1bc670e5"] capabilities:KBKeyCapabilitiesEncrypt|KBKeyCapabilitiesVerify];
  
  KBKeyBundle *publicKey2 = [[KBKeyBundle alloc] initWithBundle:[self loadFile:@"user2_public.asc"] userName:nil fingerprint:@"664cf3d7151ed6e38aa051c54bf812991a9c76ab" secret:NO];
  [keyRing addKey:publicKey2 PGPKeyIds:@[@"4bf812991a9c76ab"] capabilities:KBKeyCapabilitiesEncrypt|KBKeyCapabilitiesVerify];

  //  KBKeyBundle *privateKey1 = [[KBKeyBundle alloc] initWithBundle:[self loadFile:@"user1_private.asc"] userName:@"gabrielhlocal2" fingerprint:@"afb10f6a5895f5b1d67851861296617a289d5c6b" secret:YES];
  //  [keyRing addKey:privateKey1 keyIds:@[@"d53374f55303d0ea"] capabilities:KBKeyCapabilitiesDecrypt];
  //  [keyRing addKey:privateKey1 keyIds:@[@"89ae977e1bc670e5"] capabilities:KBKeyCapabilitiesSign];
  

//  KBKeyBundle *privateKey2 = [[KBKeyBundle alloc] initWithBundle:[self loadFile:@"user2_private.asc"] userName:nil fingerprint:@"664cf3d7151ed6e38aa051c54bf812991a9c76ab" secret:YES];
//  [keyRing addKey:privateKey2 keyIds:@[@"49d182780818ea2d"] capabilities:KBKeyCapabilitiesDecrypt];
//  [keyRing addKey:privateKey2 keyIds:@[@"4bf812991a9c76ab"] capabilities:KBKeyCapabilitiesSign];
  
  return keyRing;
}

- (KBCrypto *)crypto {
  //KBCryptoPasswordBlock passwordBlock = ^(id<KBKey> key, KBCryptoPasswordCompletionBlock completionBlock) { completionBlock(TEST_PASSWORD); };
  KBCrypto *crypto = [[KBCrypto alloc] initWithKeyRing:[self keyRing]];
  //crypto.passwordBlock = passwordBlock;
  return crypto;
}

- (void)testEncryptDecrypt:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  [crypto encryptText:@"This is a secret message" keyBundle:[self loadFile:@"user1_public.asc"] success:^(NSString *messageArmored) {
    [crypto decryptMessageArmored:messageArmored keyBundle:[self loadFile:@"user1_private.asc"] password:TEST_PASSWORD success:^(NSString *plainText, NSArray *verifiedSigners) {
      GRAssertEqualStrings(plainText, @"This is a secret message");
      
      completion();
    } failure:GRUErrorHandler(self)];
  } failure:GRUErrorHandler(self)];
}

- (void)testEncryptDecryptWithGPG:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  [crypto encryptText:@"This is a secret message" keyBundle:[self loadFile:@"user2_public.asc"] success:^(NSString *messageArmored) {
    [crypto decryptMessageArmored:messageArmored keyBundle:[self loadFile:@"user2_private.asc"] password:TEST_PASSWORD success:^(NSString *plainText, NSArray *verifiedSigners) {
      GRAssertEqualStrings(plainText, @"This is a secret message");
      completion();
    } failure:GRUErrorHandler(self)];
  } failure:GRUErrorHandler(self)];
}

- (void)testSignVerify:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  [crypto signText:@"This is a secret message" keyBundle:[self loadFile:@"user1_private.asc"] password:TEST_PASSWORD success:^(NSString *clearTextArmored) {
    [crypto verifyMessageArmored:clearTextArmored success:^(NSString *plainText, NSArray *verifiedSigners) {
      GRAssertEqualStrings(plainText, @"This is a secret message");
      completion();
    } failure:GRUErrorHandler(self)];
  } failure:GRUErrorHandler(self)];
}

- (void)testSignVerifyWithGPG:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  [crypto signText:@"This is a secret message" keyBundle:[self loadFile:@"user2_private.asc"] password:TEST_PASSWORD success:^(NSString *clearTextArmored) {
    [crypto verifyMessageArmored:clearTextArmored success:^(NSString *plainText, NSArray *verifiedSigners) {
      GRAssertEqualStrings(plainText, @"This is a secret message");
      completion();
    } failure:GRUErrorHandler(self)];
  } failure:GRUErrorHandler(self)];
}

- (void)testEncryptSignDecryptVerify:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  [crypto encryptText:@"This is a secret signed message" keyBundle:[self loadFile:@"user2_public.asc"] keyBundleForSign:[self loadFile:@"user1_private.asc"] passwordForSign:TEST_PASSWORD success:^(NSString *messageArmored) {
    [crypto decryptMessageArmored:messageArmored keyBundle:[self loadFile:@"user2_private.asc"] password:TEST_PASSWORD success:^(NSString *plainText, NSArray *signers) {
      GRAssertEqualStrings(plainText, @"This is a secret signed message");
      GRAssertEqualStrings(@"afb10f6a5895f5b1d67851861296617a289d5c6b", [signers[0] keyFingerprint]);
      GRAssertTrue([signers[0] isVerified]);
      completion();
    } failure:GRUErrorHandler(self)];
  } failure:GRUErrorHandler(self)];
}

- (void)testEncryptSignDecryptVerifyFromGPG:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  [crypto encryptText:@"This is a secret signed message" keyBundle:[self loadFile:@"user1_public.asc"] keyBundleForSign:[self loadFile:@"user2_private.asc"] passwordForSign:TEST_PASSWORD success:^(NSString *messageArmored) {
    [crypto decryptMessageArmored:messageArmored keyBundle:[self loadFile:@"user1_private.asc"] password:TEST_PASSWORD success:^(NSString *plainText, NSArray *signers) {
      GRAssertEqualStrings(plainText, @"This is a secret signed message");
      GRAssertEqualObjects(@"664cf3d7151ed6e38aa051c54bf812991a9c76ab", [signers[0] keyFingerprint]);
      GRAssertFalse([signers[0] isVerified]);
      completion();
    } failure:GRUErrorHandler(self)];
  } failure:GRUErrorHandler(self)];
}

- (void)testDecrypt:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  
  NSArray *files = @[@"user1_message_kb.asc", @"user1_message_gpg1.asc", @"user1_message_gpg2.asc"];
  __block NSInteger index = 0;
  for (NSString *file in files) {
    GRTestLog(@"Testing file: %@", file);
    NSString *messageArmored = [self loadFile:file];
    [crypto decryptMessageArmored:messageArmored keyBundle:[self loadFile:@"user1_private.asc"] password:TEST_PASSWORD success:^(NSString *plainText, NSArray *signers) {
      GHDebug(@"Decrypted: %@", file);
      GRAssertEqualStrings(plainText, @"this is a test message to gabrielhlocal2");
      
      if (++index == [files count]) completion();
    } failure:GRUErrorHandler(self)];
  }
}

- (void)testDecryptWithP3SKB:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  [crypto decryptMessageArmored:[self loadFile:@"user1_message_kb.asc"] keyBundle:[self loadFile:@"user1_private.p3skb"] password:TEST_PASSWORD success:^(NSString *plainText, NSArray *signers) {
    GRAssertEqualStrings(plainText, @"this is a test message to gabrielhlocal2");
    completion();
  } failure:GRUErrorHandler(self)];
}

- (void)testDecryptSignedMultipleRecipients:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  
  NSArray *recipients = @[@"user1_private.asc", @"user2_private.asc"];
  __block NSInteger index = 0;
  for (NSString *recipient in recipients) {
    // user1_message_gpgui.asc is encrypted for user1 and user2 and signed by user2, using the gpg services encrypt gui
    [crypto decryptMessageArmored:[self loadFile:@"user1_message_gpgui.asc"] keyBundle:[self loadFile:recipient] password:TEST_PASSWORD success:^(NSString *plainText, NSArray *signers) {
      GRAssertEqualStrings(plainText, @"this is a signed test message");
      GRAssertEqualObjects(@"664cf3d7151ed6e38aa051c54bf812991a9c76ab", [signers[0] keyFingerprint]);
      if (++index == [recipients count]) completion();
    } failure:GRUErrorHandler(self)];
  }
}

- (void)testVerify:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  
  NSDictionary *files = @{
                     @"user1_clearsign_kb.asc": @"this is a signed message from gabrielhlocal2",
                     @"user1_clearsign_gpg1.asc": @"this is a signed message from gabrielhlocal2",
                     @"user1_sign_gpg1.asc": @"this is a signed message from gabrielhlocal2",
                     @"user1_sign_gpg2.asc": @"this is a signed message from gabrielhlocal2",
                     @"user2_clearsign_gpg2.asc": @"this is a signed message from gabrielhgpg2"};
  
  __block NSInteger index = 0;
  for (NSString *file in files) {
    NSString *messageArmored = [self loadFile:file];
    [crypto verifyMessageArmored:messageArmored success:^(NSString *plainText, NSArray *verifiedSigners) {
      GHDebug(@"Verified: %@, %@", file, plainText);
      NSString *expected = files[file];
      GRAssertEqualStrings(expected, plainText);

      if (++index == [files count]) completion();
    } failure:GRUErrorHandler(self)];
  }
}

- (void)testVerifyFailure:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  
  NSString *messageArmored = [self loadFile:@"user1_clearsign_fail.asc"];
  
  [crypto verifyMessageArmored:messageArmored success:^(NSString *plainText, NSArray *verifiedSigners) {
    GRFail(@"Should fail");
  } failure:^(NSError *error) {
    NSLog(@"Failed ok: %@", error);
    completion();
  }];
}

- (void)testGenerateKey:(dispatch_block_t)completion {
  KBCrypto *crypto = [[KBCrypto alloc] init];
  [crypto generateKeyWithUserName:@"keybase.io/crypto" userEmail:@"user@email.com" password:@"toomanysecrets" success:^(NSString *privateKeyArmored, NSString *publicKeyArmored, NSString *keyId) {
  
    GRTestLog(@"privateKeyArmored: %@", privateKeyArmored);
    //GRTestLog(@"publicKeyArmored: %@", publicKeyArmored);
    GRTestLog(@"keyId: %@", keyId);
    
    completion();
    
  } failure:GRUErrorHandler(self)];
}

- (void)testDearmorArmorPrivate:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  NSString *privateKeyArmored = [self loadFile:@"user1_private.asc"];
  
  [crypto dearmor:privateKeyArmored success:^(NSData *privateKeyData) {
    [crypto armor:privateKeyData messageType:KBMessageTypePrivateKey success:^(NSString *privateKeyRearmored) {
      NSString *key1 = [privateKeyArmored gh_lastSplitWithString:@"\n\n" options:0];
      NSString *key2 = [privateKeyRearmored gh_lastSplitWithString:@"\n\n" options:0];
      GRAssertEqualStrings(key1, key2);
      completion();
    } failure:GRUErrorHandler(self)];
  } failure:GRUErrorHandler(self)];
}

- (void)testDearmorArmorPublic:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  NSString *publicKeyArmored = [self loadFile:@"user1_public.asc"];
  [crypto dearmor:publicKeyArmored success:^(NSData *publicKeyData) {
    [crypto armor:publicKeyData messageType:KBMessageTypePublicKey success:^(NSString *publicKeyRearmored) {
      NSString *key1 = [publicKeyArmored gh_lastSplitWithString:@"\n\n" options:0];
      NSString *key2 = [publicKeyRearmored gh_lastSplitWithString:@"\n\n" options:0];
      GRAssertEqualStrings(key1, key2);
      
      completion();
    } failure:GRUErrorHandler(self)];
  } failure:GRUErrorHandler(self)];
}

@end
