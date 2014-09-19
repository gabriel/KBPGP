//
//  KBSigner.h
//  KBCrypto
//
//  Created by Gabriel on 8/7/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "KBPGPKey.h"

@interface KBSigner : NSObject

@property (readonly) KBPGPKey *PGPKey;

- (instancetype)initWithPGPKey:(KBPGPKey *)PGPKey;

@end
