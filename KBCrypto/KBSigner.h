//
//  KBSigner.h
//  KBCrypto
//
//  Created by Gabriel on 8/7/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface KBSigner : NSObject

@property (readonly) NSString *keyFingerprint;
@property (readonly, getter=isVerified) BOOL verified;

- (instancetype)initWithKeyFingerprint:(NSString *)keyFingerprint verified:(BOOL)verified;

@end
