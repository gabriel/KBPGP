//
//  KBSigner.m
//  KBCrypto
//
//  Created by Gabriel on 8/7/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBSigner.h"

@interface KBSigner ()
@property NSString *keyFingerprint;
@property (getter=isVerified) BOOL verified;
@end

@implementation KBSigner

- (instancetype)initWithKeyFingerprint:(NSString *)keyFingerprint verified:(BOOL)verified {
  if ((self = [super init])) {
    _keyFingerprint = keyFingerprint;
    _verified = verified;
  }
  return self;
}

- (NSUInteger)hash {
  return [_keyFingerprint hash];
}

- (BOOL)isEqual:(id)object {
  return ([object isKindOfClass:KBSigner.class] && [[object keyFingerprint] isEqualToString:_keyFingerprint] && [object isVerified] == _verified);
}

@end
