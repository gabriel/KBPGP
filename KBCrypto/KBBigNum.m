//
//  KBKeyGen.m
//  KBCrypto
//
//  Created by Gabriel on 10/17/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBBigNum.h"

#import <GHKit/GHKit.h>
#include <openssl/bn.h>

@implementation KBBigNum

+ (NSString *)generatePrime:(int)bits {
  //GHDebug(@"Generate prime: %d", bits);
  BIGNUM *r = BN_new();
  BN_generate_prime_ex(r, 2048, 0, NULL, NULL, NULL);
  char *h = BN_bn2dec(r);
  NSString *decStr = [NSString stringWithUTF8String:h];
  BN_free(r);
  
  //GHDebug(@"Generated random prime: %@", decStr);
  return decStr;
}

+ (NSString *)modPow:(NSString *)a p:(NSString *)p m:(NSString *)m {
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *ba = BN_new();
  BIGNUM *bp = BN_new();
  BIGNUM *bm = BN_new();
  BN_dec2bn(&ba, [a cStringUsingEncoding:NSASCIIStringEncoding]);
  BN_dec2bn(&bp, [p cStringUsingEncoding:NSASCIIStringEncoding]);
  BN_dec2bn(&bm, [m cStringUsingEncoding:NSASCIIStringEncoding]);
  
  BIGNUM *r = BN_new();
  BN_mod_exp(r, ba, bp, bm, ctx);
  
  NSString *decStr = [NSString stringWithUTF8String:BN_bn2dec(r)];
  BN_free(r);
  BN_free(ba);
  BN_free(bp);
  BN_free(bm);
  BN_CTX_free(ctx);
  return decStr;
}

+ (NSString *)modInverse:(NSString *)a m:(NSString *)m {
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *ba = BN_new();
  BIGNUM *bm = BN_new();
  BN_dec2bn(&ba, [a cStringUsingEncoding:NSASCIIStringEncoding]);
  BN_dec2bn(&bm, [m cStringUsingEncoding:NSASCIIStringEncoding]);
  
  BIGNUM *r = BN_new();
  BN_mod_inverse(r, ba, bm, ctx);
  
  NSString *decStr = [NSString stringWithUTF8String:BN_bn2dec(r)];
  BN_free(r);
  BN_free(ba);
  BN_free(bm);
  BN_CTX_free(ctx);
  return decStr;
}

@end
