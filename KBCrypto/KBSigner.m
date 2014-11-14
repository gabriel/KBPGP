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
@end

@implementation KBSigner

- (instancetype)initWithKeyFingerprint:(NSString *)keyFingerprint {
  if ((self = [super init])) {
    _keyFingerprint = keyFingerprint;
  }
  return self;
}

#pragma mark NSCoding

+ (BOOL)supportsSecureCoding { return YES; }

- (id)initWithCoder:(NSCoder *)decoder {
  if ((self = [self init])) {
    _keyFingerprint = [decoder decodeObjectOfClass:NSString.class forKey:@"keyFingerprint"];
  }
  return self;
}

- (void)encodeWithCoder:(NSCoder *)encoder {
  [encoder encodeObject:_keyFingerprint forKey:@"keyFingerprint"];
}

@end