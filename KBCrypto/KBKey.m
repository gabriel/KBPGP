//
//  KBKey.m
//  Keybase
//
//  Created by Gabriel on 7/31/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBKey.h"

#import <GHKit/GHKit.h>

NSString *KBKeyIdFromFingerprint(NSString *fingerprint) {
  if ([fingerprint length] < 16) return fingerprint;
  return [[fingerprint substringFromIndex:[fingerprint length] - 16] lowercaseString];
}

NSString *KBKeyDisplayDescription(NSString *fingerprint) {
  if ([fingerprint length] < 16) return fingerprint;
  NSString *str = [[fingerprint substringFromIndex:[fingerprint length] - 16] lowercaseString];
  return [@[[str substringWithRange:NSMakeRange(0, 4)],
            [str substringWithRange:NSMakeRange(4, 4)],
            [str substringWithRange:NSMakeRange(8, 4)],
            [str substringWithRange:NSMakeRange(12, 4)]] componentsJoinedByString:@" "];

}

NSString *KBKeyCapabilitiesDescription(KBKeyCapabilities capabilities) {
  NSMutableArray *desc = [NSMutableArray array];
  if ((capabilities & KBKeyCapabilitiesDecrypt) != 0) [desc addObject:@"Decrypt"];
  if ((capabilities & KBKeyCapabilitiesEncrypt) != 0) [desc addObject:@"Encrypt"];
  if ((capabilities & KBKeyCapabilitiesSign) != 0) [desc addObject:@"Sign"];
  if ((capabilities & KBKeyCapabilitiesVerify) != 0) [desc addObject:@"Verify"];
  return [desc componentsJoinedByString:@", "];
}


@interface KBKey ()
@property NSString *keyId;
@property NSString *bundle;
@property NSString *userName;
@property KBKeyCapabilities capabilities;
@property (getter=isPasswordProtected) BOOL passwordProtected;
@end


@implementation KBKey

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
