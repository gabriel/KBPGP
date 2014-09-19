//
//  KBSigner.m
//  KBCrypto
//
//  Created by Gabriel on 8/7/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBSigner.h"

@interface KBSigner ()
@property KBPGPKey *PGPKey;
@end

@implementation KBSigner

- (instancetype)initWithPGPKey:(KBPGPKey *)PGPKey {
  if ((self = [super init])) {
    _PGPKey = PGPKey;
  }
  return self;
}

@end
