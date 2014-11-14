//
//  KBSigner.h
//  KBCrypto
//
//  Created by Gabriel on 8/7/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "KBKey.h"

@protocol KBSigner
@property (readonly, nonatomic) NSString *keyFingerprint;
@end


@interface KBSigner : NSObject <KBSigner, NSSecureCoding>

- (instancetype)initWithKeyFingerprint:(NSString *)keyFingerprint;

@end