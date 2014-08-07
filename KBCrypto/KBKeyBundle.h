//
//  KBKeyBundle.h
//  KBCrypto
//
//  Created by Gabriel on 8/1/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "KBKey.h"

/*!
 Default key implementation.
 */
@interface KBKeyBundle : NSObject <KBKey>

- (instancetype)initWithBundle:(NSString *)bundle userName:(NSString *)userName fingerprint:(NSString *)fingerprint secret:(BOOL)secret;

@end
