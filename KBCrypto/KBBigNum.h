//
//  KBKeyGen.h
//  KBCrypto
//
//  Created by Gabriel on 10/17/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface KBBigNum : NSObject

+ (NSString *)generatePrime:(int)bits;
+ (NSString *)modPow:(NSString *)a p:(NSString *)p m:(NSString *)m;
+ (NSString *)modInverse:(NSString *)a m:(NSString *)m;

@end
