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

@interface KBPGPKeyTest : GRTestCase
@property KBCrypto *crypto;
@end

@implementation KBPGPKeyTest

- (NSString *)loadFile:(NSString *)file {
  NSString *path = [[NSBundle mainBundle] pathForResource:[file stringByDeletingPathExtension] ofType:[file pathExtension]];
  NSString *contents = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:NULL];
  NSAssert(contents, @"No contents at file: %@", file);
  return contents;
}

- (void)setUp {
  if (!_crypto) _crypto = [[KBCrypto alloc] init];
}

- (void)testSerialize:(dispatch_block_t)completion {
  NSString *bundle = [self loadFile:@"user1_private.asc"];
  [_crypto PGPKeyForKeyBundle:bundle keyBundlePassword:@"toomanysecrets" password:@"toomanysecrets2" success:^(KBPGPKey *PGPKey) {

    NSData *data = [NSKeyedArchiver archivedDataWithRootObject:PGPKey];
    KBPGPKey *PGPKey2 = [NSKeyedUnarchiver unarchiveObjectWithData:data];
    
    GRAssertEqualObjects(PGPKey2.secretKey, PGPKey.secretKey);
    
    completion();
    
  } failure:GRErrorHandler];
}

@end
