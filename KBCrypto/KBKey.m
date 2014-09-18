//
//  KBKey.m
//  KBCrypto
//
//  Created by Gabriel on 7/31/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBKey.h"

#import <GHKit/GHKit.h>

NSString *KBPGPKeyIdFromFingerprint(NSString *fingerprint) {
  if (!fingerprint) return nil;
  if ([fingerprint length] < 16) return fingerprint;
  return [[fingerprint substringFromIndex:[fingerprint length] - 16] lowercaseString];
}

NSString *NSStringFromKBKeyFingerprint(NSString *fingerprint, NSInteger indexForLineBreak) {
  NSMutableString *s = [[NSMutableString alloc] init];
  for (NSInteger i = 1; i <= fingerprint.length; i++) {
    [s appendString:[NSString stringWithFormat:@"%c", [fingerprint characterAtIndex:i-1]]];
    if (indexForLineBreak == i) {
      [s appendString:@"\n"];
    } else {
      if (i % 4 == 0) [s appendString:@" "];
    }
  }
  return [s uppercaseString];
}

NSString *NSStringFromKBKeyCapabilities(KBKeyCapabilities capabilities) {
  NSMutableArray *desc = [NSMutableArray array];
  if ((capabilities & KBKeyCapabilitiesEncrypt) != 0) [desc addObject:@"Encrypt"];
  if ((capabilities & KBKeyCapabilitiesDecrypt) != 0) [desc addObject:@"Decrypt"];
  if ((capabilities & KBKeyCapabilitiesSign) != 0) [desc addObject:@"Sign"];
  if ((capabilities & KBKeyCapabilitiesVerify) != 0) [desc addObject:@"Verify"];
  return [desc componentsJoinedByString:@", "];
}

NSString *NSStringFromKBKeyAlgorithm(KBKeyAlgorithm algorithm) {
  switch (algorithm) {
    case KBKeyAlgorithmRSA: return @"RSA";
    case KBKeyAlgorithmDSA: return @"DSA";
    case KBKeyAlgorithmElgamal: return @"Elgamal";
    case KBKeyAlgorithmECDSA: return @"ECDSA";
  }
  return @"Unknown";
}

BOOL KBHasCapabilities(KBKeyCapabilities capabilities, KBKeyCapabilities keyCapabilities) {
  return ((keyCapabilities & capabilities) != 0);
}

#import <GHKit/GHKit.h>

@interface KBKey ()
@property NSString *publicKeyBundle;
@property NSString *fingerprint;
@end


@implementation KBKey

@synthesize secretKey=_secretKey;

- (instancetype)initWithPublicKeyBundle:(NSString *)publicKeyBundle fingerprint:(NSString *)fingerprint secretKey:(P3SKB *)secretKey {
  if ((self = [super init])) {
    _publicKeyBundle = publicKeyBundle;
    _fingerprint = fingerprint;
    _secretKey = secretKey;
  }
  return self;
}

- (NSString *)description {
  return GHDescription(@"fingerprint");
}

#pragma mark NSCoding

+ (BOOL)supportsSecureCoding { return YES; }

- (id)initWithCoder:(NSCoder *)decoder {
  if ((self = [self init])) {
    _publicKeyBundle = [decoder decodeObjectOfClass:NSString.class forKey:@"publicKeyBundle"];
    _fingerprint = [decoder decodeObjectOfClass:NSString.class forKey:@"fingerprint"];
    _secretKey = [decoder decodeObjectOfClass:P3SKB.class forKey:@"secretKey"];
  }
  return self;
}

- (void)encodeWithCoder:(NSCoder *)encoder {
  [encoder encodeObject:_publicKeyBundle forKey:@"publicKeyBundle"];
  [encoder encodeObject:_fingerprint forKey:@"fingerprint"];
  [encoder encodeObject:_secretKey forKey:@"secretKey"];
}

@end
