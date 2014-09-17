//
//  KBPGPKeyTest.m
//  KBCrypto
//
//  Created by Gabriel on 9/8/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import <GRUnit/GRUnit.h>

#import "KBPGPKey.h"
#import "KBCrypto.h"
#import "KBTestKeyRing.h"

@interface KBPGPKeyTest : GRTestCase
@property KBCrypto *crypto;
@end

@implementation KBPGPKeyTest

- (instancetype)init {
  if ((self = [super init])) {
    _crypto = [[KBCrypto alloc] init];
  }
  return self;
}

- (void)tearDown {
  [_crypto clearContext];
}

- (void)testSerialize:(dispatch_block_t)completion {
  NSString *bundle = [KBTestKeyRing loadFile:@"user1_private.asc"];
  [_crypto PGPKeyForKeyBundle:bundle keyBundlePassword:@"toomantsecrets" password:@"toomanysecrets2" success:^(KBPGPKey *PGPKey) {

    NSData *data = [NSKeyedArchiver archivedDataWithRootObject:PGPKey];
    KBPGPKey *PGPKey2 = [NSKeyedUnarchiver unarchiveObjectWithData:data];
    
    GRAssertEqualObjects(PGPKey2.secretKey, PGPKey.secretKey);
    
    completion();
    
  } failure:GRErrorHandler];
}

@end
