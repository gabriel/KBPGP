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
@property NSString *userName;
@property NSString *fingerprint;
@property (getter=isSecret) BOOL secret;
@end


@implementation KBKeyBundle

- (instancetype)initWithBundle:(NSString *)bundle userName:(NSString *)userName fingerprint:(NSString *)fingerprint secret:(BOOL)secret {
  if ((self = [super init])) {
    _bundle = bundle;
    _userName = userName;
    _fingerprint = fingerprint;
    _secret = secret;
  }
  return self;
}

- (NSString *)description {
  return GHDescription(@"userName", @"fingerprint", @"secret");
}

@end
