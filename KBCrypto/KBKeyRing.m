//
//  KBKeyRing.m
//  KBCrypto
//
//  Created by Gabriel on 7/29/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBKeyRing.h"
#import "KBCrypto.h"
#import "KBSigner.h"

#import <ObjectiveSugar/ObjectiveSugar.h>
#import <GHKit/GHKit.h>

@interface KBKeyRing ()
@property NSMutableDictionary *keys;
@end

@implementation KBKeyRing

- (id)init {
  if ((self = [super init])) {
    _keys = [NSMutableDictionary dictionary];
  }
  return self;
}

- (void)addKey:(id<KBKey>)key PGPKeyIds:(NSArray *)PGPKeyIds capabilities:(KBKeyCapabilities)capabilities {
  GHDebug(@"%@ %@", PGPKeyIds, NSStringFromKBKeyCapabilities(capabilities));
  
  for (NSString *keyId in PGPKeyIds) {
    NSMutableArray *keys = _keys[[keyId lowercaseString]];
    if (!keys) {
      keys = [NSMutableArray array];
      _keys[keyId] = keys;
    }
    [keys addObject:@{
                      @"key": key,
                      @"capabilities": @(capabilities)
                      }];
  }
}

- (void)lookupPGPKeyIds:(NSArray *)PGPKeyIds capabilities:(KBKeyCapabilities)capabilities success:(void (^)(NSArray *keyBundles))success failure:(void (^)(NSError *error))failure {
  
  NSMutableArray *found = [NSMutableArray array];
  for (NSString *keyId in PGPKeyIds) {
    NSArray *keys = _keys[[keyId lowercaseString]];
    if (keys) {
      for (NSDictionary *key in keys) {
        if (([key[@"capabilities"] integerValue] & capabilities) != 0) {
          [found addObject:key[@"key"]];
        }
      }
    }
  }
  
  GHDebug(@"Lookup key ids: %@, %@; %d", PGPKeyIds, NSStringFromKBKeyCapabilities(capabilities), (int)[found count]);
  
  if ([found count] > 0) {
    if (_process) {
      _process(found, ^(NSArray *bundles) {
        success(bundles);
      });
    } else {
      success([found map:^id(id<KBKey> key) {
        return key.publicKeyBundle;
      }]);
    }
  } else {
    success(@[]);
    //failure(KBCNSError(KBCryptoErrorCodeKeyNotFound, NSStringWithFormat(@"No key for ids: %@", PGPKeyIds)));
  }
}

- (void)verifyKeyFingerprints:(NSArray *)keyFingerprints success:(void (^)(NSArray *signers))success failure:(void (^)(NSError *error))failure {
  NSArray *signers = [keyFingerprints map:^id(NSString *keyFingerprint) {
    return [[KBSigner alloc] initWithKeyFingerprint:keyFingerprint verified:NO];
  }];
  success(signers);
}

- (void)fetch:(NSArray *)keyIds ops:(NSUInteger)ops success:(JSValue *)success failure:(JSValue *)failure {
  GHWeakSelf blockSelf = self;
  [self lookupPGPKeyIds:keyIds capabilities:ops success:^(NSArray *keyBundles) {
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
