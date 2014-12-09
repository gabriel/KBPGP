//
//  KBPGPMessage.h
//  KBCrypto
//
//  Created by Gabriel on 9/19/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface KBPGPMessage : NSObject <NSSecureCoding>

@property (readonly) NSArray */*of NSString*/verifyKeyIds; // From
@property (readonly) NSArray */*of NSString*/decryptKeyIds; // To
@property (readonly) NSString *bundle; // Armored message bundle

@property (readonly) NSData *data; // Unencrypted data (maybe nil if not decrypted)
@property (readonly) NSArray */*of id<KBSigner>*/signers;
@property (readonly) NSArray */*of NSString */warnings;

+ (KBPGPMessage *)messageWithVerifyKeyIds:(NSArray *)verifyKeyIds decryptKeyIds:(NSArray *)decryptKeyIds bundle:(NSString *)bundle data:(NSData *)data signers:(NSArray *)signers warnings:(NSArray *)warnings;

- (NSString *)text;

- (void)updateData:(NSData *)data;

@end
