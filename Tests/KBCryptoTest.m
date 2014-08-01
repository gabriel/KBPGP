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

- (id<KBKeyRing>)testKeyRing {
  KBKeyRing *keyRing = [[KBKeyRing alloc] init];
  
  [keyRing addKey:[[KBKeyBundle alloc] initWithKeyId:@"89ae977e1bc670e5" bundle:[self loadFile:@"gabrielhlocal2_public.asc"]  userName:@"gabrielhlocal2" capabilities:KBKeyCapabilitiesEncrypt|KBKeyCapabilitiesVerify passwordProtected:NO]];
  [keyRing addKey:[[KBKeyBundle alloc] initWithKeyId:@"d53374f55303d0ea" bundle:[self loadFile:@"gabrielhlocal2_private.asc"]  userName:@"gabrielhlocal2" capabilities:KBKeyCapabilitiesDecrypt passwordProtected:YES]];
  [keyRing addKey:[[KBKeyBundle alloc] initWithKeyId:@"89ae977e1bc670e5" bundle:[self loadFile:@"gabrielhlocal2_private.asc"]  userName:@"gabrielhlocal2" capabilities:KBKeyCapabilitiesSign passwordProtected:YES]];
  
  [keyRing addKey:[[KBKeyBundle alloc] initWithKeyId:@"4bf812991a9c76ab" bundle:[self loadFile:@"gabrielhgpg2_public.asc"]  userName:nil capabilities:KBKeyCapabilitiesEncrypt|KBKeyCapabilitiesVerify  passwordProtected:NO]];
  [keyRing addKey:[[KBKeyBundle alloc] initWithKeyId:@"49d182780818ea2d" bundle:[self loadFile:@"gabrielhgpg2_private.asc"]  userName:nil capabilities:KBKeyCapabilitiesDecrypt passwordProtected:YES]];
  [keyRing addKey:[[KBKeyBundle alloc] initWithKeyId:@"4bf812991a9c76ab" bundle:[self loadFile:@"gabrielhgpg2_private.asc"]  userName:nil capabilities:KBKeyCapabilitiesSign passwordProtected:YES]];
  
  return keyRing;
}

- (KBCrypto *)crypto {
  KBCryptoPasswordBlock passwordBlock = ^(id<KBKey> key, KBCryptoPasswordCompletionBlock completionBlock) { completionBlock(TEST_PASSWORD); };
  KBCrypto *crypto = [[KBCrypto alloc] initWithKeyRing:[self testKeyRing]];
  crypto.passwordBlock = passwordBlock;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
  crypto.completionQueue = dispatch_get_current_queue();
#pragma GCC diagnostic pop
  return crypto;
}

- (void)testEncryptDecrypt {
  KBCrypto *crypto = [self crypto];
  NSArray *keyIds = @[@"89ae977e1bc670e5", @"4bf812991a9c76ab"];
  [crypto prepare];
  for (NSString *keyId in keyIds) {
    [crypto encryptText:@"This is a secret message" keyIds:@[keyId] success:^(NSString *messageArmored) {
      [crypto decryptMessageArmored:messageArmored success:^(NSString *plainText, NSArray *verifiedSigners) {
        GHAssertEqualStrings(plainText, @"This is a secret message", nil);
      } failure:GHUErrorHandler(self)];
    } failure:GHUErrorHandler(self)];
  }
  GHUAssertTrue([crypto wait:10]);
}

- (void)testSignVerify {
  KBCrypto *crypto = [self crypto];
  NSArray *keyIds = @[@"89ae977e1bc670e5", @"4bf812991a9c76ab"];
  
  [crypto prepare];
  for (NSString *keyId in keyIds) {
    [crypto signText:@"This is a secret message" keyIds:@[keyId] success:^(NSString *clearTextArmored) {
      [crypto verifyMessageArmored:clearTextArmored success:^(NSString *plainText, NSArray *verifiedSigners) {
        GHAssertEqualStrings(plainText, @"This is a secret message", nil);
      } failure:GHUErrorHandler(self)];
    } failure:GHUErrorHandler(self)];
  }
  GHUAssertTrue([crypto wait:10]);
}

- (void)testEncryptSignDecryptVerify {
  KBCrypto *crypto = [self crypto];

  NSArray *keyIds = @[@"89ae977e1bc670e5", @"4bf812991a9c76ab"];
  
  for (NSString *keyId in keyIds) {
    [crypto prepare];
    [crypto encryptAndSignText:@"This is a secret signed message" encryptForKeyIds:@[keyId] signForKeyIds:@[keyId] success:^(NSString *messageArmored) {
      [crypto decryptMessageArmored:messageArmored success:^(NSString *plainText, NSArray *verifiedSigners) {
        GHAssertEqualStrings(plainText, @"This is a secret signed message", nil);
      } failure:GHUErrorHandler(self)];
    } failure:GHUErrorHandler(self)];
    GHUAssertTrue([crypto wait:10]);
  }
}

- (void)testDecrypt {
  KBCrypto *crypto = [self crypto];
  
  NSArray *files = @[@"gabrielhlocal2_message_kb.asc", @"gabrielhlocal2_message_gpg1.asc", @"gabrielhlocal2_message_gpg2.asc"];
  
  for (NSString *file in files) {
    [crypto prepare];
    GHTestLog(@"Testing file: %@", file);
    NSString *messageArmored = [self loadFile:file];
    [crypto decryptMessageArmored:messageArmored success:^(NSString *plainText, NSArray *verifiedSigners) {
      GHTestLog(@"Decrypted: %@", file);
      GHAssertEqualStrings(plainText, @"this is a test message to gabrielhlocal2", nil);
    } failure:GHUErrorHandler(self)];
    GHUAssertTrue([crypto wait:10]);
  }
}

- (void)testVerify {
  KBCrypto *crypto = [self crypto];
  
  NSDictionary *files = @{
                     @"gabrielhlocal2_clearsign_kb.asc": @"this is a signed message from gabrielhlocal2",
                     @"gabrielhlocal2_clearsign_gpg1.asc": @"this is a signed message from gabrielhlocal2",
                     @"gabrielhlocal2_sign_gpg1.asc": @"this is a signed message from gabrielhlocal2",
                     @"gabrielhlocal2_sign_gpg2.asc": @"this is a signed message from gabrielhlocal2",
                     @"gabrielhgpg2_clearsign_gpg2.asc": @"this is a signed message from gabrielhgpg2"};
  
  [crypto prepare];
  for (NSString *file in files) {
    NSString *messageArmored = [self loadFile:file];
    [crypto verifyMessageArmored:messageArmored success:^(NSString *plainText, NSArray *verifiedSigners) {
      GHDebug(@"Verified: %@, %@", file, plainText);
      NSString *expected = files[file];
      GHAssertEqualStrings(expected, plainText, nil);
    } failure:GHUErrorHandler(self)];
  }
  
  GHUAssertTrue([crypto wait:10]);
}

- (void)testVerifyFailure {
  KBCrypto *crypto = [self crypto];
  
  NSString *messageArmored = [self loadFile:@"gabrielhlocal2_clearsign_fail.asc"];
  
  [crypto prepare];
  
  [crypto verifyMessageArmored:messageArmored success:^(NSString *plainText, NSArray *verifiedSigners) {
    GHUFail(@"Should fail");
  } failure:^(NSError *error) {
    NSLog(@"Failed ok: %@", error);
  }];
  
  GHUAssertTrue([crypto wait:10]);
}

- (void)testGenerateKey {
  KBCrypto *crypto = [[KBCrypto alloc] init];
  
  [crypto prepare];
  [crypto generateKeyWithNumBits:4096 numBitsSubKeys:2048 userName:@"keybase.io/crypto" userEmail:@"user@email.com" password:@"toomanysecrets" success:^(NSString *privateKeyArmored, NSString *publicKeyArmored, NSString *keyId) {
  
    GHTestLog(@"privateKeyArmored: %@", privateKeyArmored);
    //GHTestLog(@"publicKeyArmored: %@", publicKeyArmored);
    GHTestLog(@"keyId: %@", keyId);
    
  } failure:GHUErrorHandler(self)];

  GHUAssertTrue([crypto wait:600]);
}

- (void)testDearmorArmor {
  KBCrypto *crypto = [self crypto];
  NSString *privateKeyArmored = [self loadFile:@"gabrielhlocal2_private.asc"];
  
  [crypto prepare];
  
  [crypto dearmor:privateKeyArmored success:^(NSData *privateKeyData) {
    [crypto armor:privateKeyData messageType:KBMessageTypePrivateKey success:^(NSString *privateKeyRearmored) {
      NSString *key1 = [privateKeyArmored gh_lastSplitWithString:@"\n\n" options:0];
      NSString *key2 = [privateKeyRearmored gh_lastSplitWithString:@"\n\n" options:0];
      GHUAssertEqualStrings(key1, key2);
    } failure:GHUErrorHandler(self)];
  } failure:GHUErrorHandler(self)];
  
  NSString *publicKeyArmored = [self loadFile:@"gabrielhlocal2_public.asc"];
  [crypto dearmor:publicKeyArmored success:^(NSData *publicKeyData) {
    [crypto armor:publicKeyData messageType:KBMessageTypePublicKey success:^(NSString *publicKeyRearmored) {
      NSString *key1 = [publicKeyArmored gh_lastSplitWithString:@"\n\n" options:0];
      NSString *key2 = [publicKeyRearmored gh_lastSplitWithString:@"\n\n" options:0];
      GHUAssertEqualStrings(key1, key2);
    } failure:GHUErrorHandler(self)];
  } failure:GHUErrorHandler(self)];
  
  GHUAssertTrue([crypto wait:10]);
}

@end
