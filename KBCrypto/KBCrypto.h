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

#import "KBPGPKeyRing.h"
#import "KBSigner.h"

#import <TSTripleSec/P3SKB.h>

typedef NS_ENUM (NSInteger, KBCryptoErrorCode) {
  KBCryptoErrorCodeDefault = -1,
  KBCryptoErrorCodeCancelled = -2,
  KBCryptoErrorCodeKeyNotFound = -3,
};

/*!
 Keybase PGP.
 */
@interface KBCrypto : NSObject

// Defaults to main queue
@property dispatch_queue_t completionQueue;

@property id<KBKeyRing> keyRing;

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
 @param text Text to sign
 @param keyBundle Bundle to sign with. Key bundle can be armored private PGP key, or base64 encoded P3SKB bundle.
 @param password Password for keyBundle
 */
- (void)signText:(NSString *)text keyBundle:(NSString *)keyBundle password:(NSString *)password success:(void (^)(NSString *armoredSignature))success failure:(void (^)(NSError *error))failure;

/*!
 Decrypt (and verify if signed).
 
 The keyring will be used to lookup keys to verify signatures.
 
 @param messageArmored Armored PGP message
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
 
 The keyring will be used to lookup keys to verify signatures.
 
 @param messageArmored Armored PGP message
 @param success
 
    - *plainText*: Verified text
    - *signers*: Signed with key fingerprints
 
 @param failure
 
    - *error*: Error
 
 */
- (void)verifyMessageArmored:(NSString *)messageArmored success:(void (^)(NSString *plainText, NSArray *signers))success failure:(void (^)(NSError *error))failure;


/*!
 Unbox (decrypt and/or verify).
 
 The keyring will be used to lookup keys to decrypt and verify.
 
 @param messageArmored Armored PGP message
 @param success
 
 - *plainText*: Verified text
 - *signers*: Signed with key fingerprints
 
 @param failure
 
 - *error*: Error
 
 */
- (void)unbox:(NSString *)messageArmored success:(void (^)(NSString *plainText, NSArray *signers))success failure:(void (^)(NSError *failure))failure;

/*!
 Armor public key.
 */
- (void)armoredKeyBundleFromPublicKey:(NSData *)data success:(void (^)(NSString *keyBundle))success failure:(void (^)(NSError *failure))failure;

/*!
 Amored key bundle from PGP key.
 Can be a public or private armored key.
 */
- (void)armoredKeyBundleFromPGPKey:(KBPGPKey *)PGPKey previousPassword:(NSString *)previousPassword password:(NSString *)password success:(void (^)(NSString *encoded))success failure:(void (^)(NSError *error))failure;

/*!
 Armored private key bundle from P3SKB.
 */
- (void)armoredKeyBundleFromSecretKey:(P3SKB *)secretKey previousPassword:(NSString *)previousPassword password:(NSString *)password success:(void (^)(NSString *encoded))success failure:(void (^)(NSError *failure))failure;

/*!
 Get an armored public key bundle from any type of private bundle.
 */
- (void)armoredPublicKeyBundleFromKeyBundle:(NSString *)keyBundle success:(void (^)(NSString *keyBundle))success failure:(void (^)(NSError *error))failure;

/*!
 Dearmor. Can be a armored pgp key or message.
 */
- (void)dearmor:(NSString *)armored success:(void (^)(NSData *data))success failure:(void (^)(NSError *failure))failure;

/*!
 Generates key pair.
 Uses RSA with appropriate defaults.
 */
- (void)generateKeyWithUserName:(NSString *)userName userEmail:(NSString *)userEmail keyAlgorithm:(KBKeyAlgorithm)keyAlgorithm password:(NSString *)password progress:(BOOL (^)(KBKeyGenProgress *progress))progress success:(void (^)(P3SKB *privateKey, NSString *publicKeyArmored, NSString *keyFingerprint))success failure:(void (^)(NSError *error))failure;

/*!
 Load PGP key info from bundle.

 If you don't specify a password, the secretKey property will not be set.
 
 @param keyBundle Armored private or public key.
 @param keyBundlePassword If private key, password for private key part.
 @param password Password New password to set using P3SKB.
 */
- (void)PGPKeyForKeyBundle:(NSString *)keyBundle keyBundlePassword:(NSString *)keyBundlePassword password:(NSString *)password success:(void (^)(KBPGPKey *PGPKey))success failure:(void (^)(NSError *error))failure;

/*!
 Generate PGP key from secret key.
 */
- (void)PGPKeyForSecretKey:(P3SKB *)secretKey success:(void (^)(KBPGPKey *PGPKey))success failure:(void (^)(NSError *error))failure;

/*!
 Strip password from armored key bundle.
 */
- (void)setPasswordForArmoredKeyBundle:(NSString *)armoredKeyBundle previousPassword:(NSString *)previousPassword password:(NSString *)password success:(void (^)(NSString *keyBundle))success failure:(void (^)(NSError *error))failure;

#pragma mark Debugging

- (void)clearContext;

@end


// Some defines
#define KBCOrNull(obj) (obj ? obj : NSNull.null)
#define KBCIfNull(obj, val) ([obj isEqual:NSNull.null] ? val : obj)

#define KBCNSError(CODE, MESSAGE) [NSError errorWithDomain:NSStringFromClass([self class]) code:CODE userInfo:@{NSLocalizedDescriptionKey:MESSAGE}]
