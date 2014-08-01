//
//  KBKeyRings.h
//  Keybase
//
//  Created by Gabriel on 7/31/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBKeyRing.h"

/*!
 Key ring interface that wraps multiple key rings.
 For example, this might:
 
 KBLocalKeyRing *localKeyRing = ...;
 KBClientKeyRing *clientKeyRing = ...;
 
 KBKeyRings *keyRings = [[KBKeyRings alloc] initWithKeyRings:@[localKeyRing, clientKeyRing]];
 
 */
@interface KBKeyRings : NSObject <KBKeyRing>

- (instancetype)initWithKeyRings:(NSArray */*of id<KeyRing>*/)keyRings;

@end
