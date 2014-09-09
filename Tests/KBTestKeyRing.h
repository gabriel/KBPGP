//
//  KBTestKeyRing.h
//  KBCrypto
//
//  Created by Gabriel on 8/7/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBKeyRing.h"

@interface KBTestKeyRing : KBKeyRing

+ (NSData *)loadBase64Data:(NSString *)file;
+ (NSString *)loadFile:(NSString *)file;

- (void)addVerifiedKeyFingerprint:(NSString *)keyFingerprint;

@end
