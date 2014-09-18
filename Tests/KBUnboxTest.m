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
    for (P3SKB *secretKey in secretKeys) {
      [blockSelf.crypto armoredKeyBundleFromSecretKey:secretKey password:@"toomanysecrets2" keyBundlePassword:nil success:^(NSString *keyBundle) {
        [keyBundles addObject:keyBundle];
        if (++count == [secretKeys count]) completion(keyBundles);
      } failure:^(NSError *error) {
        if (++count == [secretKeys count]) completion(keyBundles);
      }];
    }
  };
  
  KBPGPKeyRing *keyRing = [[KBPGPKeyRing alloc] init];
  [_crypto setKeyRing:keyRing passwordBlock:passwordBlock];
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
  [_crypto unboxMessageArmored:messageArmored success:^(NSString *plainText, NSArray *signers, NSArray *warnings, NSArray *fetches) {
    GRAssertEqualStrings(plainText, @"this is a signed test message");
    completion();
  } failure:GRErrorHandler];
}

- (void)testUnboxMissingSignerKey:(dispatch_block_t)completion {
  NSString *messageArmored = [self loadFile:@"user1_message_unk.asc"]; // Encrypted to alice and user1, signed by alice. Alice is an unknown key
  [_crypto unboxMessageArmored:messageArmored success:^(NSString *plainText, NSArray *signers, NSArray *warnings, NSArray *fetches) {
    GRAssertEqualStrings(plainText, @"unknown signer (alice)");
    completion();
  } failure:GRErrorHandler];
}

@end
