//
//  KBKey.h
//  Keybase
//
//  Created by Gabriel on 7/31/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM (NSUInteger, KBKeyCapabilities) {
  KBKeyCapabilitiesEncrypt = 1 << 0,
  KBKeyCapabilitiesDecrypt = 1 << 1,
  KBKeyCapabilitiesVerify = 1 << 2,
  KBKeyCapabilitiesSign = 1 << 3,
};

@protocol KBKey
@property (readonly) NSString *keyId;
@property (readonly) NSString *bundle;
@property (readonly) NSString *userName;
@property (readonly) KBKeyCapabilities capabilities;
- (BOOL)isPasswordProtected;
@end

NSString *KBKeyIdFromFingerprint(NSString *fingerprint);

NSString *KBKeyDisplayDescription(NSString *fingerprint);

NSString *KBKeyCapabilitiesDescription(KBKeyCapabilities capabilities);
