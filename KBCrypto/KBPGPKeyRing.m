//
//  KBPGPKeyRing.m
//  KBCrypto
//
//  Created by Gabriel on 9/16/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBPGPKeyRing.h"

@interface KBPGPKeyRing ()
@property NSMutableDictionary *keys;
@end

@implementation KBPGPKeyRing

- (id)init {
  if ((self = [super init])) {
    _keys = [NSMutableDictionary dictionary];
  }
  return self;
}

- (void)addPGPKey:(KBPGPKey *)PGPKey {
  [self addKey:PGPKey PGPKeyIds:@[PGPKey.keyId] capabilities:PGPKey.capabilities];  
  for (KBPGPSubKey *subKey in PGPKey.subKeys) {
    [self addKey:PGPKey PGPKeyIds:@[subKey.keyId] capabilities:subKey.capabilities];
  }
}

@end
