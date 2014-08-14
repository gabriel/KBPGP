//
//  KBKey.h
//  KBCrypto
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

typedef NS_ENUM (NSUInteger, KBKeyAlgorithm) {
  KBKeyAlgorithmRSA = 1,
  KBKeyAlgorithmECC = 2 
};

typedef NS_ENUM (NSUInteger, KBKeyFlags) {
  KBKeyFlagsCertifyKeys = 0x1,
  KBKeyFlagsSighData = 0x2,
  KBKeyFlagsEncryptComm = 0x4,
  KBKeyFlagsStorage = 0x8,
  KBKeyFlagsPrivateSplit = 0x10,
  KBKeyFlagsAuth = 0x20,
  KBKeyFlagsShared = 0x80,
};

@protocol KBKey <NSObject>
@property (readonly) NSString *bundle;
@property (readonly) NSString *fingerprint;
- (BOOL)isSecret;

@optional
// If secret
- (NSData *)decryptKeyWithPassword:(NSString *)password error:(NSError * __autoreleasing *)error;
@end

NSString *KBPGPKeyIdFromFingerprint(NSString *fingerprint);

NSString *KBKeyDisplayDescription(NSString *fingerprint);

NSString *KBKeyCapabilitiesDescription(KBKeyCapabilities capabilities);
