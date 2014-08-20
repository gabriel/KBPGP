//
//  KBTestKeyRing.m
//  KBCrypto
//
//  Created by Gabriel on 8/7/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBTestKeyRing.h"
#import "KBSigner.h"

#import <ObjectiveSugar/ObjectiveSugar.h>

@interface KBTestKeyRing ()
@property NSMutableSet *verifiedKeyFingerprints;
@end


@implementation KBTestKeyRing

- (void)addVerifiedKeyFingerprint:(NSString *)keyFingerprint {
  if (!_verifiedKeyFingerprints) _verifiedKeyFingerprints = [NSMutableSet set];
  [_verifiedKeyFingerprints addObject:keyFingerprint];
}

- (void)verifyKeyFingerprints:(NSArray *)keyFingerprints success:(void (^)(NSArray *signers))success failure:(void (^)(NSError *error))failure {
  __weak KBTestKeyRing *blockSelf = self;
  NSArray *s = [keyFingerprints map:^id(NSString *keyFingerprint) {
    return [[KBSigner alloc] initWithKeyFingerprint:keyFingerprint verified:([blockSelf.verifiedKeyFingerprints containsObject:keyFingerprint])];
  }];
  success(s);
}

@end
