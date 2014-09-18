//
//  KBPGPKeyRing.h
//  KBCrypto
//
//  Created by Gabriel on 9/16/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "KBKeyRing.h"
#import "KBPGPKey.h"

@interface KBPGPKeyRing : NSObject <KBKeyRing>

- (void)addPGPKey:(KBPGPKey *)PGPKey;

@end
