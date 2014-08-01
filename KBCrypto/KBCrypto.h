//
//  KBCrypto.h
//  Keybase
//
//  Created by Gabriel on 7/1/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBKeyRing.h"
#import "KBMessage.h"
#import "KBKeyBundle.h"
#import "KBSigner.h"

typedef void (^KBCryptoPasswordCompletionBlock)(NSString *password);
typedef void (^KBCryptoPasswordBlock)(id<KBKey> key, KBCryptoPasswordCompletionBlock completionBlock);


/*!
 PGP.
 */
@interface KBCrypto : NSObject

/*!
 Password promot block.
 For decrypt or sign, this must be set to return a valid password.
 */
@property (copy) KBCryptoPasswordBlock passwordBlock;

/*!
 Create with key ring.
 @param keyRing Key ring
 */
- (instancetype)initWithKeyRing:(id<KBKeyRing>)keyRing;

/*!
 Encrypt, using the key ring.
 */
- (void)encryptText:(NSString *)text keyIds:(NSArray *)keyIds success:(void (^)(NSString *messageArmored))success failure:(void (^)(NSError *error))failure;

/*!
 Encrypt, specifying a key bundle.
 */
- (void)encryptText:(NSString *)text keyBundle:(NSString *)keyBundle success:(void (^)(NSString *messageArmored))success failure:(void (^)(NSError *error))failure;

/*!
 Encrypt and sign.
 */
- (void)encryptAndSignText:(NSString *)text encryptForKeyIds:(NSArray *)encryptForKeyIds signForKeyIds:(NSArray *)signForKeyIds success:(void (^)(NSString *messageArmored))success failure:(void (^)(NSError *error))failure;

/*!
 Sign (clearsign), using the key ring.
 */
- (void)signText:(NSString *)text keyIds:(NSArray *)keyIds success:(void (^)(NSString *clearTextArmored))success failure:(void (^)(NSError *error))failure;

/*!
 Sign (clearsign), specifying a key bundle and password.
 */
- (void)signText:(NSString *)text keyBundle:(NSString *)keyBundle password:(NSString *)password success:(void (^)(NSString *clearTextArmored))success failure:(void (^)(NSError *error))failure;

/*!
 Decrypt (and verify if signed).
 
 @param messageArmored
 @param success
  
    - *plainText*: Decrypted/verified text
    - *verifiedSigners*: Array of [KBSigner]
 
 @param failure
 
    - *error*: Error
 
 */
- (void)decryptMessageArmored:(NSString *)messageArmored success:(void (^)(NSString *plainText, NSArray *verifiedSigners))success failure:(void (^)(NSError *error))failure;

/*!
 Verify.
 
 @param messageArmored
 @param success
 
    - *plainText*: Verified text
    - *verifiedSigners*: Array of [KBSigner] that were verified
 
 @param failure
 
    - *error*: Error
 
 */
- (void)verifyMessageArmored:(NSString *)messageArmored success:(void (^)(NSString *plainText, NSArray *verifiedSigners))success failure:(void (^)(NSError *error))failure;

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
 Generates public/private key pair with 2 subkeys for encrypting and signing.
 */
- (void)generateKeyWithNumBits:(NSUInteger)numBits numBitsSubKeys:(NSUInteger)numBitsSubKeys userName:(NSString *)userName userEmail:(NSString *)userEmail password:(NSString *)password success:(void (^)(NSString *privateKeyArmored, NSString *publicKeyArmored, NSString *keyId))success failure:(void (^)(NSError *error))failure;

#pragma mark -

/*!
 If you are going to call wait and make the calls sychronous you need to call prepare first.
 */
- (void)prepare;

/*!
 Wait for the dispatch queue/group to finish.
 This should only be used for debug or testing purposes.
 
 @param timeout
 @result NO if timed out
 */
- (BOOL)wait:(NSTimeInterval)timeout;

/*!
 Queue for success/failure blocks.
 Defaults to main queue if nil.
 */
@property dispatch_queue_t completionQueue;

@end


// Some defines
#define KBCOrNull(obj) (obj ? obj : NSNull.null)
#define KBCIfNull(obj, val) ([obj isEqual:NSNull.null] ? val : obj)

#define KBCNSError(CODE, MESSAGE) [NSError errorWithDomain:NSStringFromClass([self class]) code:CODE userInfo:@{NSLocalizedDescriptionKey:MESSAGE}]
