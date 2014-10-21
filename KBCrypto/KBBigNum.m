//
//  KBKeyGen.m
//  KBCrypto
//
//  Created by Gabriel on 10/17/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBBigNum.h"

#import <GHKit/GHKit.h>
#import <NAChloride/NARandom.h>

#include <openssl/bn.h>
#include <openssl/rand.h>

@implementation KBBigNum

+ (void)ensureSeed {
  // OpenSSL is probably using /dev/urandom to seed itself autotmatically but
  // lets use the Security framework to do it which is guaranteed to be /dev/urandom (or better).
  static dispatch_once_t onceToken = 0;
  dispatch_once(&onceToken, ^{
    NSData *data = [NARandom randomData:520 error:nil];
    RAND_seed([data bytes], (int)[data length]);
  });
}

+ (NSString *)generatePrime:(int)bits {
  [self ensureSeed];
  
  //GHDebug(@"Generate prime: %d", bits);
  BIGNUM *r = BN_new();
  BN_generate_prime_ex(r, bits, 0, NULL, NULL, NULL);
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
