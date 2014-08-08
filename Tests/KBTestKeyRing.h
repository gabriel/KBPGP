//
//  KBTestKeyRing.h
//  KBCrypto
//
//  Created by Gabriel on 8/7/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBKeyRing.h"

@interface KBTestKeyRing : KBKeyRing

- (void)addVerifiedKeyFingerprint:(NSString *)keyFingerprint;

@end
