#import <GHUnit/GHUnit.h>

@interface KBCryptoTest : GHTestCase
@end

#import "KBCrypto.h"

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
  KBKeyRing *keyRing = [[KBKeyRing alloc] init];
  
  KBKeyBundle *publicKey1 = [[KBKeyBundle alloc] initWithBundle:[self loadFile:@"user1_public.asc"] userName:@"gabrielhlocal2" fingerprint:@"AFB10F6A5895F5B1D67851861296617A289D5C6B" secret:NO];
  [keyRing addKey:publicKey1 keyIds:@[@"89ae977e1bc670e5"] capabilities:KBKeyCapabilitiesEncrypt|KBKeyCapabilitiesVerify];
  
//  KBKeyBundle *privateKey1 = [[KBKeyBundle alloc] initWithBundle:[self loadFile:@"user1_private.asc"] userName:@"gabrielhlocal2" fingerprint:@"AFB10F6A5895F5B1D67851861296617A289D5C6B" secret:YES];
//  [keyRing addKey:privateKey1 keyIds:@[@"d53374f55303d0ea"] capabilities:KBKeyCapabilitiesDecrypt];
//  [keyRing addKey:privateKey1 keyIds:@[@"89ae977e1bc670e5"] capabilities:KBKeyCapabilitiesSign];
  
  
  KBKeyBundle *publicKey2 = [[KBKeyBundle alloc] initWithBundle:[self loadFile:@"user2_public.asc"] userName:nil fingerprint:@"664CF3D7151ED6E38AA051C54BF812991A9C76AB" secret:NO];
  [keyRing addKey:publicKey2 keyIds:@[@"4bf812991a9c76ab"] capabilities:KBKeyCapabilitiesEncrypt|KBKeyCapabilitiesVerify];
  
//  KBKeyBundle *privateKey2 = [[KBKeyBundle alloc] initWithBundle:[self loadFile:@"user2_private.asc"] userName:nil fingerprint:@"664CF3D7151ED6E38AA051C54BF812991A9C76AB" secret:YES];
//  [keyRing addKey:privateKey2 keyIds:@[@"49d182780818ea2d"] capabilities:KBKeyCapabilitiesDecrypt];
//  [keyRing addKey:privateKey2 keyIds:@[@"4bf812991a9c76ab"] capabilities:KBKeyCapabilitiesSign];
  
  return keyRing;
}

- (KBCrypto *)crypto {
  //KBCryptoPasswordBlock passwordBlock = ^(id<KBKey> key, KBCryptoPasswordCompletionBlock completionBlock) { completionBlock(TEST_PASSWORD); };
  KBCrypto *crypto = [[KBCrypto alloc] initWithKeyRing:[self keyRing]];
  //crypto.passwordBlock = passwordBlock;
//#pragma GCC diagnostic push
//#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
//  crypto.completionQueue = dispatch_get_current_queue();
//#pragma GCC diagnostic pop
  return crypto;
}

- (void)testEncryptDecrypt:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  [crypto encryptText:@"This is a secret message" keyBundle:[self loadFile:@"user1_public.asc"] success:^(NSString *messageArmored) {
    [crypto decryptMessageArmored:messageArmored keyBundle:[self loadFile:@"user1_private.asc"] password:TEST_PASSWORD success:^(NSString *plainText, NSArray *verifiedSigners) {
      GHAssertEqualStrings(plainText, @"This is a secret message", nil);
      
      completion();
    } failure:GHUErrorHandler(self)];
  } failure:GHUErrorHandler(self)];
}

- (void)testEncryptDecryptWithGPG:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  [crypto encryptText:@"This is a secret message" keyBundle:[self loadFile:@"user2_public.asc"] success:^(NSString *messageArmored) {
    [crypto decryptMessageArmored:messageArmored keyBundle:[self loadFile:@"user2_private.asc"] password:TEST_PASSWORD success:^(NSString *plainText, NSArray *verifiedSigners) {
      GHAssertEqualStrings(plainText, @"This is a secret message", nil);
      completion();
    } failure:GHUErrorHandler(self)];
  } failure:GHUErrorHandler(self)];
}

- (void)testSignVerify:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  [crypto signText:@"This is a secret message" keyBundle:[self loadFile:@"user1_private.asc"] password:TEST_PASSWORD success:^(NSString *clearTextArmored) {
    [crypto verifyMessageArmored:clearTextArmored success:^(NSString *plainText, NSArray *verifiedSigners) {
      GHAssertEqualStrings(plainText, @"This is a secret message", nil);
      completion();
    } failure:GHUErrorHandler(self)];
  } failure:GHUErrorHandler(self)];
}

- (void)testSignVerifyWithGPG:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  [crypto signText:@"This is a secret message" keyBundle:[self loadFile:@"user2_private.asc"] password:TEST_PASSWORD success:^(NSString *clearTextArmored) {
    [crypto verifyMessageArmored:clearTextArmored success:^(NSString *plainText, NSArray *verifiedSigners) {
      GHAssertEqualStrings(plainText, @"This is a secret message", nil);
      completion();
    } failure:GHUErrorHandler(self)];
  } failure:GHUErrorHandler(self)];
}

- (void)testEncryptSignDecryptVerify:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  [crypto encryptText:@"This is a secret signed message" keyBundle:[self loadFile:@"user2_public.asc"] keyBundleForSign:[self loadFile:@"user1_private.asc"] passwordForSign:TEST_PASSWORD success:^(NSString *messageArmored) {
    [crypto decryptMessageArmored:messageArmored keyBundle:[self loadFile:@"user2_private.asc"] password:TEST_PASSWORD success:^(NSString *plainText, NSArray *verifiedSigners) {
      GHAssertEqualStrings(plainText, @"This is a secret signed message", nil);
      completion();
    } failure:GHUErrorHandler(self)];
  } failure:GHUErrorHandler(self)];
}

- (void)testEncryptSignDecryptVerifyFromGPG:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  [crypto encryptText:@"This is a secret signed message" keyBundle:[self loadFile:@"user1_public.asc"] keyBundleForSign:[self loadFile:@"user2_private.asc"] passwordForSign:TEST_PASSWORD success:^(NSString *messageArmored) {
    [crypto decryptMessageArmored:messageArmored keyBundle:[self loadFile:@"user1_private.asc"] password:TEST_PASSWORD success:^(NSString *plainText, NSArray *verifiedSigners) {
      GHAssertEqualStrings(plainText, @"This is a secret signed message", nil);
      completion();
    } failure:GHUErrorHandler(self)];
  } failure:GHUErrorHandler(self)];
}

- (void)testDecrypt:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  
  NSArray *files = @[@"user1_message_kb.asc", @"user1_message_gpg1.asc", @"user1_message_gpg2.asc"];
  __block NSInteger index = 0;
  for (NSString *file in files) {
    GHTestLog(@"Testing file: %@", file);
    NSString *messageArmored = [self loadFile:file];
    [crypto decryptMessageArmored:messageArmored keyBundle:[self loadFile:@"user1_private.asc"] password:TEST_PASSWORD success:^(NSString *plainText, NSArray *verifiedSigners) {
      GHDebug(@"Decrypted: %@", file);
      GHAssertEqualStrings(plainText, @"this is a test message to gabrielhlocal2", nil);
      
      if (++index == [files count]) completion();
    } failure:GHUErrorHandler(self)];
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
      GHAssertEqualStrings(expected, plainText, nil);

      if (++index == [files count]) completion();
    } failure:GHUErrorHandler(self)];
  }
}

- (void)testVerifyFailure:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  
  NSString *messageArmored = [self loadFile:@"user1_clearsign_fail.asc"];
  
  [crypto verifyMessageArmored:messageArmored success:^(NSString *plainText, NSArray *verifiedSigners) {
    GHUFail(@"Should fail");
  } failure:^(NSError *error) {
    NSLog(@"Failed ok: %@", error);
    completion();
  }];
}

- (void)testGenerateKey:(dispatch_block_t)completion {
  KBCrypto *crypto = [[KBCrypto alloc] init];
  [crypto generateKeyWithNumBits:4096 numBitsSubKeys:2048 userName:@"keybase.io/crypto" userEmail:@"user@email.com" password:@"toomanysecrets" success:^(NSString *privateKeyArmored, NSString *publicKeyArmored, NSString *keyId) {
  
    GHTestLog(@"privateKeyArmored: %@", privateKeyArmored);
    //GHTestLog(@"publicKeyArmored: %@", publicKeyArmored);
    GHTestLog(@"keyId: %@", keyId);
    
    completion();
    
  } failure:GHUErrorHandler(self)];
}

- (void)testDearmorArmorPrivate:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  NSString *privateKeyArmored = [self loadFile:@"user1_private.asc"];
  
  [crypto dearmor:privateKeyArmored success:^(NSData *privateKeyData) {
    [crypto armor:privateKeyData messageType:KBMessageTypePrivateKey success:^(NSString *privateKeyRearmored) {
      NSString *key1 = [privateKeyArmored gh_lastSplitWithString:@"\n\n" options:0];
      NSString *key2 = [privateKeyRearmored gh_lastSplitWithString:@"\n\n" options:0];
      GHUAssertEqualStrings(key1, key2);
      completion();
    } failure:GHUErrorHandler(self)];
  } failure:GHUErrorHandler(self)];
}

- (void)testDearmorArmorPublic:(dispatch_block_t)completion {
  KBCrypto *crypto = [self crypto];
  NSString *publicKeyArmored = [self loadFile:@"user1_public.asc"];
  [crypto dearmor:publicKeyArmored success:^(NSData *publicKeyData) {
    [crypto armor:publicKeyData messageType:KBMessageTypePublicKey success:^(NSString *publicKeyRearmored) {
      NSString *key1 = [publicKeyArmored gh_lastSplitWithString:@"\n\n" options:0];
      NSString *key2 = [publicKeyRearmored gh_lastSplitWithString:@"\n\n" options:0];
      GHUAssertEqualStrings(key1, key2);
      
      completion();
    } failure:GHUErrorHandler(self)];
  } failure:GHUErrorHandler(self)];
}

@end
