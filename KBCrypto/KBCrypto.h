//
//  KBCrypto.h
//  KBCrypto
//
//  Created by Gabriel on 7/1/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBKeyRing.h"
#import "KBMessage.h"
#import "KBKeyBundle.h"

//typedef void (^KBCryptoPasswordCompletionBlock)(NSString *password);
//typedef void (^KBCryptoPasswordBlock)(id<KBKey> key, KBCryptoPasswordCompletionBlock completionBlock);

/*!
 Keybase PGP.
 */
@interface KBCrypto : NSObject

//@property (copy) KBCryptoPasswordBlock passwordBlock;

/*!
 Create with key ring.
 @param keyRing Key ring
 */
- (instancetype)initWithKeyRing:(id<KBKeyRing>)keyRing;

/*!
 Encrypt.
 @param text Text to encrypt
 @param keyBundle Bundle to encrypt with
 */
- (void)encryptText:(NSString *)text keyBundle:(NSString *)keyBundle success:(void (^)(NSString *messageArmored))success failure:(void (^)(NSError *error))failure;

/*!
 Encrypt and sign.
 @param text Text to encrypt
 @param keyBundle Bundle to encrypt with
 @param keyBundleForSign
 @param passwordForSign Password for keyBundleForSign
 */
- (void)encryptText:(NSString *)text keyBundle:(NSString *)keyBundle keyBundleForSign:(NSString *)keyBundleForSign passwordForSign:(NSString *)passwordForSign success:(void (^)(NSString *messageArmored))success failure:(void (^)(NSError *error))failure;

/*!
 Sign (clearsign).
 */
- (void)signText:(NSString *)text keyBundle:(NSString *)keyBundle password:(NSString *)password success:(void (^)(NSString *clearTextArmored))success failure:(void (^)(NSError *error))failure;

/*!
 Decrypt (and verify if signed).
 
 @param messageArmored
 @param keyBundle
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
 
 @param messageArmored
 @param success
 
    - *plainText*: Verified text
    - *signers*: Signed with key fingerprints
 
 @param failure
 
    - *error*: Error
 
 */
- (void)verifyMessageArmored:(NSString *)messageArmored success:(void (^)(NSString *plainText, NSArray *signers))success failure:(void (^)(NSError *error))failure;

#pragma mark -

/*!
 Armor.
 */
- (void)armor:(NSData *)data messageType:(KBMessageType)messageType success:(void (^)(NSString *encoded))success failure:(void (^)(NSError *failure))failure;

/*!
 Dearmor.
 */
- (void)dearmor:(NSString *)armored success:(void (^)(NSData *data))success failure:(void (^)(NSError *failure))failure;

//
//- (void)readClearTextMessageArmored:(NSString *)clearTextMessageArmored completion:(void (^)(NSString *plainText, NSArray *keySigningIds))completion;

/*!
 Generates public/private key pair.
 */
- (void)generateKeyWithUserName:(NSString *)userName userEmail:(NSString *)userEmail password:(NSString *)password success:(void (^)(NSString *privateKeyArmored, NSString *publicKeyArmored, NSString *keyId))success failure:(void (^)(NSError *error))failure;

@end


// Some defines
#define KBCOrNull(obj) (obj ? obj : NSNull.null)
#define KBCIfNull(obj, val) ([obj isEqual:NSNull.null] ? val : obj)

#define KBCNSError(CODE, MESSAGE) [NSError errorWithDomain:NSStringFromClass([self class]) code:CODE userInfo:@{NSLocalizedDescriptionKey:MESSAGE}]
