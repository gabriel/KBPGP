//
//  KBSigner.m
//  KBCrypto
//
//  Created by Gabriel on 9/19/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBSigner.h"

@interface KBSigner ()
@property NSString *keyFingerprint;
@property KBKeyVerification verification;
@end

@implementation KBSigner

- (instancetype)initWithKeyFingerprint:(NSString *)keyFingerprint verification:(KBKeyVerification)verification {
  if ((self = [super init])) {
    _keyFingerprint = keyFingerprint;
    _verification = verification;
  }
  return self;
}

#pragma mark NSCoding

+ (BOOL)supportsSecureCoding { return YES; }

- (id)initWithCoder:(NSCoder *)decoder {
  if ((self = [self init])) {
    _keyFingerprint = [decoder decodeObjectOfClass:NSString.class forKey:@"keyFingerprint"];
    _verification = [decoder decodeIntegerForKey:@"verification"];
  }
  return self;
}

- (void)encodeWithCoder:(NSCoder *)encoder {
  [encoder encodeObject:_keyFingerprint forKey:@"keyFingerprint"];
  [encoder encodeInteger:_verification forKey:@"verification"];
}

@end