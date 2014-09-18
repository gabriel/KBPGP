//
//  KBKey.h
//  KBCrypto
//
//  Created by Gabriel on 7/31/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import <Foundation/Foundation.h>

#import <TSTripleSec/P3SKB.h>

typedef NS_ENUM (NSInteger, KBKeyCapabilities) {
  KBKeyCapabilitiesEncrypt = 1 << 0,
  KBKeyCapabilitiesDecrypt = 1 << 1,
  KBKeyCapabilitiesVerify = 1 << 2,
  KBKeyCapabilitiesSign = 1 << 3,
};

typedef NS_ENUM (NSInteger, KBKeyAlgorithm) {
  KBKeyAlgorithmRSA = 1,
  KBKeyAlgorithmElgamal = 16,
  KBKeyAlgorithmDSA = 17,
  KBKeyAlgorithmECDSA = 19
};

@protocol KBKey <NSObject>
@property (readonly) NSString *publicKeyBundle;
@property (readonly) NSString *fingerprint;
@property (nonatomic) P3SKB *secretKey;
@end

NSString *KBPGPKeyIdFromFingerprint(NSString *fingerprint);

NSString *NSStringFromKBKeyFingerprint(NSString *fingerprint, NSInteger indexForLineBreak);

NSString *NSStringFromKBKeyCapabilities(KBKeyCapabilities capabilities);

NSString *NSStringFromKBKeyAlgorithm(KBKeyAlgorithm algorithm);

BOOL KBHasCapabilities(KBKeyCapabilities capabilities, KBKeyCapabilities keyCapabilities);

/*!
 Default key implementation.
 */
@interface KBKey : NSObject <KBKey>

- (instancetype)initWithPublicKeyBundle:(NSString *)publicKeyBundle fingerprint:(NSString *)fingerprint secretKey:(P3SKB *)secretKey;

@end
