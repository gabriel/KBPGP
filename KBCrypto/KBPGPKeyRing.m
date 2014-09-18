//
//  KBPGPKeyRing.m
//  KBCrypto
//
//  Created by Gabriel on 9/16/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBPGPKeyRing.h"

#import "KBSigner.h"

#import <GHKit/GHKit.h>
#import <ObjectiveSugar/ObjectiveSugar.h>

@interface KBPGPKeyRing ()
@property NSMutableDictionary *keys;
@end

@implementation KBPGPKeyRing

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

- (void)addPGPKey:(KBPGPKey *)PGPKey {
  [self addKey:PGPKey PGPKeyIds:@[PGPKey.keyId] capabilities:PGPKey.capabilities];  
  for (KBPGPSubKey *subKey in PGPKey.subKeys) {
    [self addKey:PGPKey PGPKeyIds:@[subKey.keyId] capabilities:subKey.capabilities];
  }
}

- (void)lookupPGPKeyIds:(NSArray *)PGPKeyIds capabilities:(KBKeyCapabilities)capabilities success:(void (^)(NSArray *keys))success failure:(void (^)(NSError *error))failure {
  
  NSMutableArray *foundKeys = [NSMutableArray array];
  for (NSString *keyId in PGPKeyIds) {
    BOOL found = NO;
    NSArray *keys = _keys[[keyId lowercaseString]];
    if (keys) {
      for (NSDictionary *key in keys) {
        if (([key[@"capabilities"] integerValue] & capabilities) != 0) {
          [foundKeys addObject:key[@"key"]];
          found = YES;
        }
      }
    }
    if (!found) {
      
    }
  }
  
  GHDebug(@"Lookup key ids: %@, %@; %d", PGPKeyIds, NSStringFromKBKeyCapabilities(capabilities), (int)[foundKeys count]);
  
  success(foundKeys);
}

- (void)verifyKeyFingerprints:(NSArray *)keyFingerprints success:(void (^)(NSArray *signers))success failure:(void (^)(NSError *error))failure {
  NSArray *signers = [keyFingerprints map:^id(NSString *keyFingerprint) {
    return [[KBSigner alloc] initWithKeyFingerprint:keyFingerprint verified:NO];
  }];
  success(signers);
}

@end
