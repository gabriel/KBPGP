#import <GRUnit/GRUnit.h>

#import "KBCrypto.h"
#import "KBPGPKeyRing.h"

#import <GHKit/GHKit.h>
#import <ObjectiveSugar/ObjectiveSugar.h>

@interface KBUnboxTest : GRTestCase
@property KBCrypto *crypto;
@end

@implementation KBUnboxTest

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
  KBKeyRingPasswordBlock passwordBlock = ^(NSArray *secretKeys, KBKeyRingPasswordCompletionBlock completion) {
    __block NSInteger count = 0;
    NSMutableArray *keyBundles = [NSMutableArray array];
    for (KBPGPKey *secretKey in secretKeys) {
      NSString *keyBundle = [secretKey decryptSecretKeyArmoredWithPassword:@"toomanysecrets2" error:nil];
      [keyBundles addObject:keyBundle];
      if (++count == [secretKeys count]) completion(keyBundles);
    }
  };
  
  KBPGPKeyRing *keyRing = [[KBPGPKeyRing alloc] init];
  [_crypto setKeyRing:keyRing passwordBlock:passwordBlock];
  [_crypto PGPKeyForPublicKeyBundle:[self loadFile:@"user1_private.asc"] success:^(KBPGPKey *PGPKey1) {
    [keyRing addPGPKey:PGPKey1];
  
    [blockSelf.crypto PGPKeyForPublicKeyBundle:[self loadFile:@"user2_public.asc"] success:^(KBPGPKey *PGPKey2) {
      [keyRing addPGPKey:PGPKey2];
    
      completion();
      
    } failure:GRErrorHandler];
  } failure:GRErrorHandler];
}

- (void)testUnbox:(dispatch_block_t)completion {
  NSString *messageArmored = [self loadFile:@"user1_message_gpgui.asc"];
  GHDebug(@"Unbox");
  [_crypto unboxMessageArmored:messageArmored success:^(KBPGPMessage *message) {
    GRAssertEqualStrings(message.text, @"this is a signed test message");
    GHDebug(@"Done");
    completion();
  } failure:GRErrorHandler];
}

- (void)testUnboxMissingSignerKey:(dispatch_block_t)completion {
  NSString *messageArmored = [self loadFile:@"user1_message_unk.asc"]; // Encrypted to alice and user1, signed by alice. Alice is an unknown key
  [_crypto unboxMessageArmored:messageArmored success:^(KBPGPMessage *message) {
    GRAssertEqualStrings(message.text, @"unknown signer (alice)");
    GRAssertEqualObjects((@[@"2b9be885a5de4eb9"]), message.verifyKeyIds);
    GRAssertEqualObjects((@[@"303494a3903f2fc6", @"d53374f55303d0ea"]), message.decryptKeyIds);
    completion();
  } failure:GRErrorHandler];
}

@end
