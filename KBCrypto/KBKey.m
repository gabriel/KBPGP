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

NSString *NSStringFromKBKeyFingerprint(NSString *fingerprint) {
  if ([fingerprint length] < 16) return fingerprint;
  NSString *str = [[fingerprint substringFromIndex:[fingerprint length] - 16] lowercaseString];
  return [@[[str substringWithRange:NSMakeRange(0, 4)],
            [str substringWithRange:NSMakeRange(4, 4)],
            [str substringWithRange:NSMakeRange(8, 4)],
            [str substringWithRange:NSMakeRange(12, 4)]] componentsJoinedByString:@" "];

}

NSString *NSStringFromKBKeyCapabilities(KBKeyCapabilities capabilities) {
  NSMutableArray *desc = [NSMutableArray array];
  if ((capabilities & KBKeyCapabilitiesDecrypt) != 0) [desc addObject:@"Decrypt"];
  if ((capabilities & KBKeyCapabilitiesEncrypt) != 0) [desc addObject:@"Encrypt"];
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

#import <GHKit/GHKit.h>

@interface KBKey ()
@property NSString *bundle;
@property NSString *fingerprint;
@property (getter=isSecret) BOOL secret;
@end


@implementation KBKey

- (instancetype)initWithBundle:(NSString *)bundle fingerprint:(NSString *)fingerprint secret:(BOOL)secret {
  if ((self = [super init])) {
    _bundle = bundle;
    _fingerprint = fingerprint;
    _secret = secret;
  }
  return self;
}

- (NSString *)description {
  return GHDescription(@"fingerprint", @"secret");
}

#pragma mark NSCoding

+ (BOOL)supportsSecureCoding { return YES; }

- (id)initWithCoder:(NSCoder *)decoder {
  if ((self = [self init])) {
    _bundle = [decoder decodeObjectOfClass:[NSString class] forKey:@"bundle"];
    _fingerprint = [decoder decodeObjectOfClass:[NSString class] forKey:@"fingerprint"];
    _secret = [decoder decodeBoolForKey:@"secret"];
  }
  return self;
}

- (void)encodeWithCoder:(NSCoder *)encoder {
  [encoder encodeObject:_bundle forKey:@"bundle"];
  [encoder encodeObject:_fingerprint forKey:@"fingerprint"];
  [encoder encodeBool:_secret forKey:@"secret"];
}

@end
