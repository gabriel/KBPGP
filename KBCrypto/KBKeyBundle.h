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

- (instancetype)initWithKeyId:(NSString *)keyId bundle:(NSString *)bundle userName:(NSString *)userName capabilities:(KBKeyCapabilities)capabilities passwordProtected:(BOOL)passwordProtected;

@end
