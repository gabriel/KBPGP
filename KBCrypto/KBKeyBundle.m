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
@property NSString *keyId;
@property NSString *bundle;
@property NSString *userName;
@property KBKeyCapabilities capabilities;
@property (getter=isPasswordProtected) BOOL passwordProtected;
@end


@implementation KBKeyBundle

- (instancetype)initWithKeyId:(NSString *)keyId bundle:(NSString *)bundle userName:(NSString *)userName capabilities:(KBKeyCapabilities)capabilities passwordProtected:(BOOL)passwordProtected {
  if ((self = [super init])) {
    _keyId = keyId;
    _bundle = bundle;
    _userName = userName;
    _capabilities = capabilities;
    _passwordProtected = passwordProtected;
  }
  return self;
}

- (NSString *)description {
  return GHDescription(@"keyId", @"userName", @"capabilities", @"passwordProtected");
}

@end
