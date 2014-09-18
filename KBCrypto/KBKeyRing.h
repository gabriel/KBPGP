//
//  KBKeyRing.h
//  KBCrypto
//
//  Created by Gabriel on 9/18/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "KBKey.h"

@protocol KBKeyRing

- (void)lookupPGPKeyIds:(NSArray *)PGPKeyIds capabilities:(KBKeyCapabilities)capabilities success:(void (^)(NSArray *keys))success failure:(void (^)(NSError *error))failure;

- (void)verifyKeyFingerprints:(NSArray *)keyFingerprints success:(void (^)(NSArray *signers))success failure:(void (^)(NSError *error))failure;

@end


@interface KBKeyRingFetch : NSObject

@property NSArray *PGPKeyIds;
@property KBKeyCapabilities capabilities;

@end