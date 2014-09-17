#import <GRUnit/GRUnit.h>

#import "KBCrypto.h"
#import "KBPGPKeyRing.h"
#import "KBTestKeyRing.h"

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
  
  KBPGPKeyRing *keyRing = [[KBPGPKeyRing alloc] init];
  
  GHWeakSelf blockSelf = self;
  keyRing.process = ^(NSArray *keys, KBKeyRingProcessCompletionBlock completion) {
    NSMutableArray *keyBundles = [NSMutableArray array];
    
    NSMutableArray *publicKeys = [[keys select:^BOOL(id<KBKey> key) { return !key.secretKey; }] mutableCopy];
    NSMutableArray *secretKeys = [[keys select:^BOOL(id<KBKey> key) { return !!key.secretKey; }] mutableCopy];
    
    for (id<KBKey> key in publicKeys) {
      [keyBundles addObject:key.publicKeyBundle];
    }
    
    __block NSInteger count = 0;
    for (id<KBKey> key in secretKeys) {
      [blockSelf.crypto armoredKeyBundleFromSecretKey:key.secretKey previousPassword:@"toomanysecrets2" password:nil success:^(NSString *keyBundle) {
        [keyBundles addObject:keyBundle];
        if (++count == [secretKeys count]) completion(keyBundles);
      } failure:^(NSError *error) {
        if (++count == [secretKeys count]) completion(keyBundles);
      }];
    }
  };
  
  _crypto.keyRing = keyRing;
  [_crypto PGPKeyForKeyBundle:[self loadFile:@"user1_private.asc"] keyBundlePassword:@"toomanysecrets" password:@"toomanysecrets2" success:^(KBPGPKey *PGPKey1) {
    [keyRing addPGPKey:PGPKey1];
  
    [blockSelf.crypto PGPKeyForKeyBundle:[self loadFile:@"user2_public.asc"] keyBundlePassword:nil password:nil success:^(KBPGPKey *PGPKey2) {
      [keyRing addPGPKey:PGPKey2];
    
      completion();
      
    } failure:GRErrorHandler];
  } failure:GRErrorHandler];
}

- (void)tearDown {
  [_crypto clearContext];
}

- (void)testUnbox:(dispatch_block_t)completion {
  NSString *messageArmored = [self loadFile:@"user1_message_gpgui.asc"];
  [_crypto unbox:messageArmored success:^(NSString *plainText, NSArray *signers, NSArray *warnings) {
    GRAssertEqualStrings(plainText, @"this is a signed test message");
    completion();
  } failure:GRErrorHandler];
}

- (void)testUnboxMissingSignerKey:(dispatch_block_t)completion {
  NSString *messageArmored = [self loadFile:@"user1_message_unk.asc"];
  [_crypto unbox:messageArmored success:^(NSString *plainText, NSArray *signers, NSArray *warnings) {
    GRAssertEqualStrings(plainText, @"unknown signer (alice)");
    completion();
  } failure:GRErrorHandler];
}

@end
