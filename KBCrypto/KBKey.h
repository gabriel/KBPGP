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
  KBKeyAlgorithmElgamal = 16,
  KBKeyAlgorithmDSA = 17,
  KBKeyAlgorithmECDSA = 19
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

NSString *NSStringFromKBKeyFingerprint(NSString *fingerprint);

NSString *NSStringFromKBKeyCapabilities(KBKeyCapabilities capabilities);

NSString *NSStringFromKBKeyAlgorithm(KBKeyAlgorithm algorithm);