//
//  KBKeyRing.h
//  Keybase
//
//  Created by Gabriel on 7/31/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBKey.h"

@protocol KBKeyRing

/*!
 Lookup keys.
 @param keyIds PGP key ids
 @param capabilities Capabilities bitmask
 @param success Array of [id<KBKey>] (KBPublicKey/KBPrivateKey)
 @param failure Failure if no keys found
 */
- (void)lookupKeyIds:(NSArray *)keyIds capabilities:(KBKeyCapabilities)capabilities success:(void (^)(NSArray */*of id<KBKey>*/keys))success failure:(void (^)(NSError *error))failure;


/*!
 Verify signers.
 @param signers Array of [KBSigner]
 */
- (void)verifySigners:(NSArray *)signers success:(void (^)(NSArray *verified, NSArray *failed))success failure:(void (^)(NSError *error))failure;

@end


/*!
 Default key ring implementation.
 */
@interface KBKeyRing : NSObject <KBKeyRing>

/*!
 Add key to key ring.
 */
- (void)addKey:(KBKey *)key;

@end
