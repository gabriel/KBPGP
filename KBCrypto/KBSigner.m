//
//  KBSigner.m
//  Keybase
//
//  Created by Gabriel on 7/31/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBSigner.h"

@interface KBSigner ()
@property NSString *keyId;
@property NSString *userName;
@end

@implementation KBSigner

- (instancetype)initWithKeyId:(NSString *)keyId userName:(NSString *)userName {
  if ((self = [super init])) {
    _keyId = keyId;
    _userName = userName;
  }
  return self;
}


@end
