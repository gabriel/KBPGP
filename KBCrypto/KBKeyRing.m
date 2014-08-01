//
//  KBKeyRing.m
//  Keybase
//
//  Created by Gabriel on 7/29/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBKeyRing.h"
#import "KBSigner.h"
#import "KBCrypto.h"

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

- (void)addKey:(KBKey *)key {
  NSString *keyId = [key.keyId lowercaseString];
  NSMutableArray *keys = _keys[keyId];
  if (!keys) {
    keys = [NSMutableArray array];
    _keys[keyId] = keys;
  }
  [keys addObject:key];
}

- (void)lookupKeyIds:(NSArray *)keyIds capabilities:(KBKeyCapabilities)capabilities success:(void (^)(NSArray *keyBundles))success failure:(void (^)(NSError *error))failure {
  NSMutableArray *found = [NSMutableArray array];
  for (NSString *keyId in keyIds) {
    NSArray *keys = _keys[[keyId lowercaseString]];
    if (keys) {
      for (id<KBKey> key in keys) {
        if ((key.capabilities & capabilities) != 0) {
          [found addObject:key];
        }
      }
    }
  }
  
  GHDebug(@"Lookup key ids: %@, %@; %@", keyIds, KBKeyCapabilitiesDescription(capabilities), found);
  
  if ([found count] > 0) {
    success(found);
  } else {
    failure(KBCNSError(-1, NSStringWithFormat(@"No key for ids: %@", keyIds)));
  }
}

// This doesn't actually verify yet
- (void)verifySigners:(NSArray *)signers success:(void (^)(NSArray *verified, NSArray *failed))success failure:(void (^)(NSError *error))failure {
  NSMutableArray *verified = [NSMutableArray array];
  NSMutableArray *failed = [NSMutableArray array];
  for (KBSigner *signer in signers) {
    NSArray *keys = _keys[[signer.keyId lowercaseString]];
    if (keys) {
      for (id<KBKey> key in keys) {
        if ([signer.userName isEqual:key.userName]) {
          [verified addObject:signer];
          break;
        }
      }
      [failed addObject:signer];
    }
  }
  success(verified, failed);
}

@end
