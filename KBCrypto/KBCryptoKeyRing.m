//
//  KBKeyRing.m
//  KBCrypto
//
//  Created by Gabriel on 7/29/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBCryptoKeyRing.h"
#import "KBCrypto.h"
#import "KBSigner.h"

#import <ObjectiveSugar/ObjectiveSugar.h>
#import <GHKit/GHKit.h>

@interface KBCryptoKeyRing ()
@property id<KBKeyRing> keyRing;
@end

@implementation KBCryptoKeyRing

- (id)initWithKeyRing:(id<KBKeyRing>)keyRing {
  if ((self = [super init])) {
    _keyRing = keyRing;
  }
  return self;
}

- (void)fetchKeyBundlesForPGPKeyIds:(NSArray *)PGPKeyIds capabilities:(KBKeyCapabilities)capabilities success:(void (^)(NSArray *keyBundles))success failure:(void (^)(NSError *error))failure {
  GHWeakSelf blockSelf = self;
  [_keyRing lookupPGPKeyIds:PGPKeyIds capabilities:capabilities success:^(NSArray *keys) {
    [blockSelf processKeys:keys completion:^(NSArray *keyBundles) {
      success(keyBundles);
    }];
  } failure:failure];
}

- (void)verifyKeyFingerprints:(NSArray *)keyFingerprints success:(void (^)(NSArray *signers))success failure:(void (^)(NSError *error))failure {
  [_keyRing verifyKeyFingerprints:keyFingerprints success:success failure:failure];
}

- (void)processKeys:(NSArray *)keys completion:(void (^)(NSArray *keyBundles))completion {
  NSMutableArray *keyBundles = [NSMutableArray array];
  
  NSMutableArray *secretKeys = [NSMutableArray array];
  
  for (id<KBKey> key in keys) {
    if (key.secretKey) {
      [secretKeys addObject:key.secretKey];
    } else {
      [keyBundles addObject:key.publicKeyBundle];
    }
  }
  
  if ([secretKeys count] == 0) {
    completion(keyBundles);
    return;
  }
  
  self.passwordBlock(secretKeys, ^(NSArray *secretKeyBundles) {
    [keyBundles addObjectsFromArray:secretKeyBundles];
    completion(keyBundles);
  });
  
  if ([secretKeys count] == 0) {
    completion(@[]);
  }
}

#pragma mark Fetch (JSContext)

- (void)fetch:(NSArray *)keyIds ops:(NSUInteger)ops success:(JSValue *)success failure:(JSValue *)failure {
  GHWeakSelf blockSelf = self;
  [self fetchKeyBundlesForPGPKeyIds:keyIds capabilities:ops success:^(NSArray *keyBundles) {
    dispatch_async(blockSelf.completionQueue, ^{
      [success callWithArguments:@[keyBundles]];
    });
  } failure:^(NSError *error) {
    dispatch_async(blockSelf.completionQueue, ^{
      [failure callWithArguments:@[error.localizedDescription]];
    });
  }];
}

@end
