//
//  KBCrypto.h
//  KBCrypto
//
//  Created by Gabriel on 7/1/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBKeyRing.h"
#import "KBKeyBundle.h"
#import "KBMessage.h"
#import "KBKeygenProgress.h"

#import <TSTripleSec/P3SKB.h>

typedef NS_ENUM (NSUInteger, KBCryptoErrorCode) {
  KBCryptoErrorCodeDefault = -1,
  KBCryptoErrorCodeCancelled = -2,
};


/*!
 Keybase PGP.
 */
@interface KBCrypto : NSObject

/*!
 Create with key ring.
 @param keyRing Key ring
 */
- (instancetype)initWithKeyRing:(id<KBKeyRing>)keyRing;

/*!
 Encrypt.
 @param text Text to encrypt
 @param keyBundle Bundle to encrypt with. Key bundle can be amrored public PGP key.
 */
- (void)encryptText:(NSString *)text keyBundle:(NSString *)keyBundle success:(void (^)(NSString *messageArmored))success failure:(void (^)(NSError *error))failure;

/*!
 Encrypt and sign.
 @param text Text to encrypt
 @param keyBundle Bundle to encrypt with. Key bundle can be amrored public PGP key.
 @param keyBundleForSign Bundle to sign with. Key bundle can be armored private PGP key, or base64 encoded P3SKB bundle.
 @param passwordForSign Password for keyBundleForSign
 */
- (void)encryptText:(NSString *)text keyBundle:(NSString *)keyBundle keyBundleForSign:(NSString *)keyBundleForSign passwordForSign:(NSString *)passwordForSign success:(void (^)(NSString *messageArmored))success failure:(void (^)(NSError *error))failure;

/*!
 Sign (clearsign).
 @param text
 @param keyBundle Bundle to sign with. Key bundle can be armored private PGP key, or base64 encoded P3SKB bundle.
 @param password Password for keyBundle
 */
- (void)signText:(NSString *)text keyBundle:(NSString *)keyBundle password:(NSString *)password success:(void (^)(NSString *clearTextArmored))success failure:(void (^)(NSError *error))failure;

/*!
 Decrypt (and verify if signed).
 
 The key ring will be used to lookup keys to verify signatures if present.
 
 @param messageArmored
 @param keyBundle Bundle to decrypt with. Key bundle can be armored private PGP key, or base64 encoded P3SKB bundle.
 @param password
 @param success
  
    - *plainText*: Decrypted/verified text
    - *signers*: Signed with key fingerprints
 
 @param failure
 
    - *error*: Error
 
 */
- (void)decryptMessageArmored:(NSString *)messageArmored keyBundle:(NSString *)keyBundle password:(NSString *)password success:(void (^)(NSString *plainText, NSArray *signers))success failure:(void (^)(NSError *error))failure;

/*!
 Verify.
 
 The key ring will be used to lookup keys to verify signatures.
 
 @param messageArmored
 @param success
 
    - *plainText*: Verified text
    - *signers*: Signed with key fingerprints
 
 @param failure
 
    - *error*: Error
 
 */
- (void)verifyMessageArmored:(NSString *)messageArmored success:(void (^)(NSString *plainText, NSArray *signers))success failure:(void (^)(NSError *error))failure;

/*!
 Armor.
 */
- (void)armor:(NSData *)data messageType:(KBMessageType)messageType success:(void (^)(NSString *encoded))success failure:(void (^)(NSError *failure))failure;

/*!
 Dearmor.
 */
- (void)dearmor:(NSString *)armored success:(void (^)(NSData *data))success failure:(void (^)(NSError *failure))failure;

/*!
 Generates key pair.
 Uses RSA with appropriate defaults.
 */
- (void)generateKeyWithUserName:(NSString *)userName userEmail:(NSString *)userEmail password:(NSString *)password progress:(BOOL (^)(KBKeygenProgress *progress))progress success:(void (^)(P3SKB *privateKey, NSString *publicKeyArmored, NSString *keyFingerprint))success failure:(void (^)(NSError *error))failure;

@end


// Some defines
#define KBCOrNull(obj) (obj ? obj : NSNull.null)
#define KBCIfNull(obj, val) ([obj isEqual:NSNull.null] ? val : obj)

#define KBCNSError(CODE, MESSAGE) [NSError errorWithDomain:NSStringFromClass([self class]) code:CODE userInfo:@{NSLocalizedDescriptionKey:MESSAGE}]
