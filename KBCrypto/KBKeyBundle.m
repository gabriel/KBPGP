//
//  KBKeyBundle.m
//  KBCrypto
//
//  Created by Gabriel on 8/1/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBKeyBundle.h"

#import <GHKit/GHKit.h>

@interface KBKeyBundle ()
@property NSString *bundle;
@property NSString *fingerprint;
@property (getter=isSecret) BOOL secret;
@end


@implementation KBKeyBundle

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
