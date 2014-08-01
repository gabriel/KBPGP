//
//  KBSigner.h
//  Keybase
//
//  Created by Gabriel on 7/31/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface KBSigner : NSObject

@property (readonly) NSString *keyId;
@property (readonly) NSString *userName;

- (instancetype)initWithKeyId:(NSString *)keyId userName:(NSString *)userName;

@end
