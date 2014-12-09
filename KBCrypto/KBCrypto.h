//
//  KBCrypto.h
//  KBCrypto
//
//  Created by Gabriel on 7/1/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBKeyRing.h"
#import "KBKey.h"
#import "KBKeyGenProgress.h"
#import "KBPGPKey.h"
#import "KBSigner.h"
#import "KBCryptoKeyRing.h"
#import "KBPGPKeyRing.h"
#import "KBPGPMessage.h"
#import "KBCryptoUtil.h"
#import <TSTripleSec/P3SKB.h>


typedef NS_ENUM (NSInteger, KBCryptoErrorCode) {
  KBCryptoErrorCodeDefault = -1,
  KBCryptoErrorCodeCancelled = -2,
  KBCryptoErrorCodeKeyNotFound = -3,
};

typedef void (^KBCyptoCompletionBlock)(NSError *error);
typedef void (^KBCyptoErrorBlock)(NSError *error);
typedef void (^KBCryptoUnboxBlock)(KBPGPMessage *message);

/*!
 Keybase PGP.
 */
@interface KBCrypto : NSObject

// Defaults to main queue
@property dispatch_queue_t completionQueue;

/*!
 Set key ring.
 */
- (void)setKeyRing:(id<KBKeyRing>)keyRing passwordBlock:(KBKeyRingPasswordBlock)passwordBlock;

#pragma mark Encrypt/Decrypt/Sign/Verify/Unbox

/*!
 Encrypt.
 @param text Text to encrypt
 @param keyBundles Bundles to encrypt with. Key bundles can be amrored public PGP key or a base64 P3SKB.
 */
- (void)encryptText:(NSString *)text keyBundles:(NSArray *)keyBundles success:(void (^)(NSString *messageArmored))success failure:(KBCyptoErrorBlock)failure;

/*!
 Encrypt and sign.
 @param text Text to encrypt
 @param keyBundles Bundles to encrypt with. Key bundle can be amrored public PGP key or a base64 P3SKB.
 @param keyBundleForSign Bundle to sign with. Key bundle can be armored private PGP key, or base64 encoded P3SKB bundle.
 @param passwordForSign Password for keyBundleForSign
 */
- (void)encryptText:(NSString *)text keyBundles:(NSArray *)keyBundles keyBundleForSign:(NSString *)keyBundleForSign passwordForSign:(NSString *)passwordForSign success:(void (^)(NSString *messageArmored))success failure:(KBCyptoErrorBlock)failure;

/*!
 Sign (clearsign).
 @param text Text to sign
 @param keyBundle Bundle to sign with. Key bundle can be armored private PGP key, or base64 encoded P3SKB bundle.
 @param password Password for keyBundle
 */
- (void)signText:(NSString *)text keyBundle:(NSString *)keyBundle password:(NSString *)password success:(void (^)(NSString *armoredSignature))success failure:(KBCyptoErrorBlock)failure;

/*!
 Decrypt (and verify if signed).
 Use unbox to have the keyring lookup key information.
 
 The keyring will be used to lookup keys to verify signatures.
 
 @param messageArmored Armored PGP message
 @param keyBundle Bundle to decrypt with. Key bundle can be armored private PGP key, or base64 encoded P3SKB bundle.
 @param password Password for keyBundle
 @param success PGP Message
 @param failure Error

 */
- (void)decryptMessageArmored:(NSString *)messageArmored keyBundle:(NSString *)keyBundle password:(NSString *)password success:(KBCryptoUnboxBlock)success failure:(KBCyptoErrorBlock)failure;

/*!
 Verify.
 
 The keyring will be used to lookup keys to verify signatures.
 
 @param messageArmored Armored PGP message
 @param success PGP Message
 @param failure Error
 
 */
- (void)verifyArmored:(NSString *)armored success:(KBCryptoUnboxBlock)success failure:(KBCyptoErrorBlock)failure;

/*!
 Verify (detached).
 
 The keyring will be used to lookup keys to verify signatures.
 
 @param messageArmored Armored PGP signature
 @param data Data
 @param success PGP Message
 @param failure Error
 */
- (void)verifyArmored:(NSString *)armored data:(NSData *)data success:(dispatch_block_t)success failure:(KBCyptoErrorBlock)failure;

/*!
 Unbox (decrypt and/or verify).
 
 The keyring will be used to lookup keys to decrypt and verify.
 
 @param messageArmored Armored PGP message
 @param success PGP Message
 @param failure Error

 */
- (void)unboxMessageArmored:(NSString *)messageArmored success:(KBCryptoUnboxBlock)success failure:(KBCyptoErrorBlock)failure;

#pragma mark Armor/Dearmor

/*!
 Armor public key.
 */
- (void)armoredKeyBundleFromPublicKey:(NSData *)data success:(void (^)(NSString *keyBundle))success failure:(KBCyptoErrorBlock)failure;

/*!
 Armored private key bundle from P3SKB.
 */
- (void)armoredKeyBundleFromSecretKey:(P3SKB *)secretKey password:(NSString *)password keyBundlePassword:(NSString *)keyBundlePassword success:(void (^)(NSString *encoded))success failure:(KBCyptoErrorBlock)failure;

/*!
 Dearmor. Can be a armored pgp key or message.
 */
- (void)dearmor:(NSString *)armored success:(void (^)(NSData *data))success failure:(KBCyptoErrorBlock)failure;

#pragma mark Generate Key

/*!
 Generates key pair.
 Uses RSA with appropriate defaults.
 */
- (void)generateKeyWithUserIds:(NSArray */*of KBPGPUserId*/)userIds keyAlgorithm:(KBKeyAlgorithm)keyAlgorithm password:(NSString *)password progress:(BOOL (^)(KBKeyGenProgress *progress))progress success:(void (^)(KBPGPKey *PGPKey))success failure:(KBCyptoErrorBlock)failure;


#pragma mark PGPKey

/*!
 Generate PGP key from private key.

 @param privateKeyBundle Armored private key.
 @param keyBundlePassword Password for private key bundle
 @param password Password New password to set
 */
- (void)PGPKeyForPrivateKeyBundle:(NSString *)privateKeyBundle keyBundlePassword:(NSString *)keyBundlePassword password:(NSString *)password success:(void (^)(KBPGPKey *PGPKey))success failure:(KBCyptoErrorBlock)failure;

/*!
 Generate PGP key from public key.
 */
- (void)PGPKeyForPublicKeyBundle:(NSString *)keyBundle success:(void (^)(KBPGPKey *key))success failure:(KBCyptoErrorBlock)failure;

/*!
 Generate PGP key from secret key.
 */
- (void)PGPKeyForSecretKey:(P3SKB *)secretKey password:(NSString *)password success:(void (^)(KBPGPKey *PGPKey))success failure:(KBCyptoErrorBlock)failure;

#pragma mark Password

/*!
 Strip password from armored key bundle.
 */
- (void)setPasswordForArmoredKeyBundle:(NSString *)armoredKeyBundle previousPassword:(NSString *)previousPassword password:(NSString *)password success:(void (^)(NSString *keyBundle))success failure:(KBCyptoErrorBlock)failure;

/*!
 Check armored key bundle password.
 */
- (void)checkPasswordForArmoredKeyBundle:(NSString *)armoredKeyBundle password:(NSString *)password success:(dispatch_block_t)success failure:(KBCyptoErrorBlock)failure;

#pragma mark User Ids

- (void)setUserIds:(NSArray *)userIds PGPKey:(KBPGPKey *)PGPKey password:(NSString *)password success:(void (^)(KBPGPKey *PGPKey))success failure:(KBCyptoErrorBlock)failure;

#pragma mark

/*!
 Add armored key bundle to key ring.
 */
- (void)addArmoredKeyBundle:(NSString *)armoredKeyBundle success:(dispatch_block_t)success failure:(KBCyptoErrorBlock)failure;

#pragma mark Debugging

- (void)resetIfNotReady:(dispatch_block_t)completion;
- (void)isReady:(void (^)(BOOL ready))completion;

@end


// Some defines
#define KBCOrNull(obj) (obj ? obj : NSNull.null)
#define KBCIfNull(obj, val) ([obj isEqual:NSNull.null] ? val : obj)

#define KBCNSError(CODE, MESSAGE) [NSError errorWithDomain:NSStringFromClass([self class]) code:CODE userInfo:@{NSLocalizedDescriptionKey:MESSAGE}]
