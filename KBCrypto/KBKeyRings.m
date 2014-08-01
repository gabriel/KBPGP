//
//  KBKeyRings.m
//  Keybase
//
//  Created by Gabriel on 7/31/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBKeyRings.h"

#import <GHKit/GHKit.h>

@interface KBKeyRings ()
@property NSMutableArray *keyRings;
@end

@implementation KBKeyRings

- (instancetype)initWithKeyRings:(NSArray *)keyRings {
  if ((self = [super init])) {
    _keyRings = [keyRings mutableCopy];
  }
  return self;
}

- (void)_lookupNext:(NSUInteger)index keyIds:(NSMutableArray *)keyIds capabilities:(KBKeyCapabilities)capabilities found:(NSMutableArray *)found success:(void (^)(NSArray */*of id<KBKey>*/keys))success failure:(void (^)(NSError *error))failure {
  
  if (index == [_keyRings count]) {
    success(found);
    return;
  }
  
  GHWeakSelf blockSelf = self;
  [_keyRings[index] lookupKeyIds:keyIds capabilities:capabilities success:^(NSArray *keys) {
    for (id<KBKey> key in keys) {
      [keyIds removeObject:key.keyId];
    }
    [found addObjectsFromArray:keys];
    
    if ([keyIds count] > 0) {
      [blockSelf _lookupNext:(index + 1) keyIds:keyIds capabilities:capabilities found:found success:success failure:failure];
    } else {
      success(found);
    }
  } failure:failure];
}

- (void)lookupKeyIds:(NSArray *)keyIds capabilities:(KBKeyCapabilities)capabilities success:(void (^)(NSArray */*of id<KBKey>*/keys))success failure:(void (^)(NSError *error))failure {
  [self _lookupNext:0 keyIds:[keyIds mutableCopy] capabilities:capabilities found:[NSMutableArray array] success:success failure:failure];
}

- (void)_verifyNext:(NSUInteger)index signers:(NSMutableArray *)signers verified:(NSMutableArray *)verified success:(void (^)(NSArray *verified, NSArray *failed))success failure:(void (^)(NSError *error))failure {
  
  if (index == [_keyRings count]) {
    success(verified, signers);
    return;
  }

  GHWeakSelf blockSelf = self;
  [_keyRings[index] verifySigners:signers success:^(NSArray *verifiedNext, NSArray *failed) {
    [signers removeObjectsInArray:verifiedNext];
    [verified addObjectsFromArray:verifiedNext];
    
    if ([failed count] > 0) {
      [blockSelf _verifyNext:(index + 1) signers:signers verified:verified success:success failure:failure];
    } else {
      success(verified, failed);
    }
  } failure:failure];
}

- (void)verifySigners:(NSArray *)signers success:(void (^)(NSArray *verified, NSArray *failed))success failure:(void (^)(NSError *error))failure {
  [self _verifyNext:0 signers:[signers mutableCopy] verified:[NSMutableArray array] success:success failure:failure];
}


@end
