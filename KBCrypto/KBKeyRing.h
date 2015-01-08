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

@end
