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
@property NSMutableDictionary *keyLookup;
@property NSMutableArray *PGPKeys;
@end

@implementation KBPGPKeyRing

- (id)init {
  if ((self = [super init])) {
    _keyLookup = [NSMutableDictionary dictionary];
    _PGPKeys = [NSMutableArray array];
  }
  return self;
}

- (void)_addPGPKey:(KBPGPKey *)PGPKey PGPKeyIds:(NSArray *)PGPKeyIds capabilities:(KBKeyCapabilities)capabilities {
  GHDebug(@"%@ %@", PGPKeyIds, NSStringFromKBKeyCapabilities(capabilities));
  
  [_PGPKeys addObject:PGPKey];
  for (NSString *keyId in PGPKeyIds) {
    NSMutableArray *keys = _keyLookup[[keyId lowercaseString]];
    if (!keys) {
      keys = [NSMutableArray array];
      _keyLookup[keyId] = keys;
    }
    [keys addObject:@{
                      @"key": PGPKey,
                      @"capabilities": @(capabilities)
                      }];
  }
}

- (void)addPGPKey:(KBPGPKey *)PGPKey {
  [self _addPGPKey:PGPKey PGPKeyIds:@[PGPKey.keyId] capabilities:PGPKey.capabilities];
  for (KBPGPSubKey *subKey in PGPKey.subKeys) {
    [self _addPGPKey:PGPKey PGPKeyIds:@[subKey.keyId] capabilities:subKey.capabilities];
  }
}

- (KBPGPKey *)PGPKeyFromFingerprint:(NSString *)fingerprint {
  return [_PGPKeys detect:^BOOL(KBPGPKey *PGPKey) { return [PGPKey.fingerprint isEqual:fingerprint]; }];
}

- (void)lookupPGPKeyIds:(NSArray *)PGPKeyIds capabilities:(KBKeyCapabilities)capabilities success:(void (^)(NSArray *keys))success failure:(void (^)(NSError *error))failure {
  NSMutableArray *foundKeys = [NSMutableArray array];
  for (NSString *keyId in PGPKeyIds) {
    NSArray *keys = _keyLookup[[keyId lowercaseString]];
    if (keys) {
      for (NSDictionary *key in keys) {
        if (([key[@"capabilities"] integerValue] & capabilities) != 0) {
          [foundKeys addObject:key[@"key"]];
        }
      }
    }
  }
  
  GHDebug(@"Lookup key ids: %@, %@; %d", PGPKeyIds, NSStringFromKBKeyCapabilities(capabilities), (int)[foundKeys count]);
  
  success(foundKeys);
}

- (void)verifyKeyFingerprints:(NSArray *)keyFingerprints success:(void (^)(NSArray *signers))success failure:(void (^)(NSError *error))failure {
  NSMutableArray *signers = [NSMutableArray array];
  for (NSString *keyFingerprint in keyFingerprints) {
    KBPGPKey *PGPKey = [self PGPKeyFromFingerprint:keyFingerprint];
    if (PGPKey) [signers addObject:[[KBSigner alloc] initWithKeyFingerprint:PGPKey.fingerprint]];
  }
  success(signers);
}

@end
