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
@property (readonly) NSString *bundle; // Always the public key bundle (for private key, see secretKey property)
@property (readonly) NSString *fingerprint;

@property (readonly) NSString *keyId;
@property (readonly) KBPGPKeyFlags flags;
@property (readonly) NSDate *date;
@property (readonly) NSUInteger numBits;
@property (readonly) KBKeyAlgorithm algorithm;
@property (readonly, getter=isSelfSigned) BOOL selfSigned;

@property (readonly) NSArray *subKeys;
@property (readonly) NSArray *userIds;

// This is the only modifiable property. Allows you to add secret part to public PGP key.
@property (nonatomic) P3SKB *secretKey;

/*!
 Get the primary or first user id.
 */
- (KBPGPUserId *)primaryUserId;

/*!
 User ids, except for the one returned by userId.
 */
- (NSArray *)alternateUserIds;

- (NSString *)displayDescription;

- (NSString *)typeDescription;

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

- (NSString *)userIdDescription:(NSString *)joinedByString;

@end