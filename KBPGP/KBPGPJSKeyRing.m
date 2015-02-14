//
//  KBPGPJSKeyRing.m
//  KBPGP
//
//  Created by Gabriel on 7/29/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBPGPJSKeyRing.h"
#import "KBPGP.h"
#import "KBSigner.h"

#import <ObjectiveSugar/ObjectiveSugar.h>
#import <GHKit/GHKit.h>

@interface KBPGPJSKeyRing ()
@property id<KBKeyRing> keyRing;
@end

@implementation KBPGPJSKeyRing

- (id)initWithKeyRing:(id<KBKeyRing>)keyRing {
  if ((self = [super init])) {
    _keyRing = keyRing;
  }
  return self;
}

- (void)fetchKeyBundlesForPGPKeyIds:(NSArray *)PGPKeyIds capabilities:(KBKeyCapabilities)capabilities success:(void (^)(NSArray *keyBundles))success failure:(void (^)(NSError *error))failure {
  GHWeakSelf blockSelf = self;
  [_keyRing lookupPGPKeyIds:PGPKeyIds capabilities:capabilities success:^(NSArray *keys) {
    if ([keys count] == 0) {
      success(@[]);
      return;
    }
    [blockSelf processKeys:keys capabilities:capabilities completion:^(NSArray *keyBundles) {
      GHDebug(@"Process keys (%d), bundles (%d)", (int)[keys count], (int)[keyBundles count]);
      success(keyBundles);
    }];
  } failure:failure];
}

- (void)processKeys:(NSArray *)keys capabilities:(KBKeyCapabilities)capabilities completion:(void (^)(NSArray *keyBundles))completion {

  NSMutableArray *keyBundles = [NSMutableArray array];
  NSMutableArray *secretKeys = [NSMutableArray array];
  
  BOOL isSignOrDecrypt = ((capabilities & KBKeyCapabilitiesDecrypt) != 0) || ((capabilities & KBKeyCapabilitiesSign) != 0);
  
  for (id<KBKey> key in keys) {
    if (key.secretKey && isSignOrDecrypt) {
      [secretKeys addObject:key];
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
