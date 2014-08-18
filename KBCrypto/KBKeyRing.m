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
  if ((capabilities & KBKeyCapabilitiesDecrypt) != 0 || (capabilities & KBKeyCapabilitiesSign) != 0) {
    failure(KBCNSError(-1, NSStringWithFormat(@"Secret keys not supported: %@", PGPKeyIds)));
    return;
  }
  
  NSMutableArray *found = [NSMutableArray array];
  for (NSString *keyId in PGPKeyIds) {
    NSArray *keys = _keys[[keyId lowercaseString]];
    if (keys) {
      for (NSDictionary *key in keys) {
        if (([key[@"capabilities"] unsignedIntegerValue] & capabilities) != 0) {
          [found addObject:key[@"key"]];
        }
      }
    }
  }
  
  GHDebug(@"Lookup key ids: %@, %@; %@", PGPKeyIds, NSStringFromKBKeyCapabilities(capabilities), found);
  
  if ([found count] > 0) {
    success(found);
  } else {
    failure(KBCNSError(-1, NSStringWithFormat(@"No key for ids: %@", PGPKeyIds)));
  }
}

- (void)verifyKeyFingerprints:(NSArray *)keyFingerprints success:(void (^)(NSArray *signers))success failure:(void (^)(NSError *error))failure {
  NSArray *signers = [keyFingerprints map:^id(NSString *keyFingerprint) {
    return [[KBSigner alloc] initWithKeyFingerprint:keyFingerprint verified:NO];
  }];
  success(signers);
}

- (void)fetch:(NSArray *)keyIds ops:(NSUInteger)ops success:(JSValue *)success failure:(JSValue *)failure {
  [self lookupPGPKeyIds:keyIds capabilities:ops success:^(NSArray *keys) {
    //NSArray *keyBundles = [keys map:^id(id<KBKey> k) { return k.bundle; }];
    NSString *keyBundle = [keys[0] bundle];
    [success callWithArguments:@[keyBundle]];
  } failure:^(NSError *error) {
    [failure callWithArguments:@[error.localizedDescription]];
  }];
}

@end
