//
//  KBPGPKey.h
//  KBCrypto
//
//  Created by Gabriel on 8/14/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "KBKey.h"
#import <Mantle/Mantle.h>
#import <TSTripleSec/P3SKB.h>

typedef NS_ENUM (NSUInteger, KBPGPKeyFlags) {
  KBPGPKeyFlagsCertifyKeys = 0x1,
  KBPGPKeyFlagsSignData = 0x2,
  KBPGPKeyFlagsEncryptComm = 0x4,
  KBPGPKeyFlagsEncryptStorage = 0x8,
  KBPGPKeyFlagsPrivateSplit = 0x10,
  KBPGPKeyFlagsAuth = 0x20,
  KBPGPKeyFlagsShared = 0x80,
};

@class KBPGPUserId;
@class KBPGPSubKey;

@interface KBPGPKey : MTLModel <KBKey, MTLJSONSerializing>
@property (readonly) NSString *keyId;
@property (readonly) KBPGPKeyFlags flags;
@property (readonly) NSDate *date;
@property (readonly) NSUInteger numBits;
@property (readonly) KBKeyAlgorithm algorithm;
@property (readonly) NSString *bundle;
@property (readonly) NSString *fingerprint;

@property (readonly) BOOL locked;
@property (readonly, getter=isSecret) BOOL secret;
@property (readonly, getter=isSelfSigned) BOOL selfSigned;

@property (readonly) NSArray *subKeys;
@property (readonly) NSArray *userIds;

/*!
 Get the primary or first user id.
 */
- (KBPGPUserId *)userId;

- (NSString *)userDescription;

- (NSString *)typeDescription;

/*!
 Set secret key.
 */
- (void)setSecretKey:(P3SKB *)secretKey;

- (NSComparisonResult)compare:(KBPGPKey *)key2;

@end


@interface KBPGPSubKey : MTLModel <MTLJSONSerializing>
@property (readonly) NSString *keyId;
@property (readonly) KBPGPKeyFlags flags;
@property (readonly) NSDate *date;
@property (readonly) NSUInteger numBits;
@property (readonly) KBKeyAlgorithm algorithm;

- (NSString *)subKeyDescription;

@end

@interface KBPGPUserId : MTLModel <MTLJSONSerializing>
@property (readonly) NSString *userName;
@property (readonly) NSString *email;
@property (readonly, getter=isPrimary) BOOL primary;
@end