//
//  KBTestKeyRing.m
//  KBCrypto
//
//  Created by Gabriel on 8/7/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBTestKeyRing.h"
#import "KBSigner.h"

#import <ObjectiveSugar/ObjectiveSugar.h>

@interface KBTestKeyRing ()
@property NSMutableSet *verifiedKeyFingerprints;
@end


@implementation KBTestKeyRing

+ (NSData *)loadBase64Data:(NSString *)file {
  NSString *path = [[NSBundle mainBundle] pathForResource:[file stringByDeletingPathExtension] ofType:[file pathExtension]];
  return [[NSData alloc] initWithBase64EncodedData:[[NSData alloc] initWithContentsOfFile:path] options:0];
}

+ (NSString *)loadFile:(NSString *)file {
  NSString *path = [[NSBundle mainBundle] pathForResource:[file stringByDeletingPathExtension] ofType:[file pathExtension]];
  NSString *contents = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:NULL];
  NSAssert(contents, @"No contents at file: %@", file);
  return contents;
}

- (void)addVerifiedKeyFingerprint:(NSString *)keyFingerprint {
  if (!_verifiedKeyFingerprints) _verifiedKeyFingerprints = [NSMutableSet set];
  [_verifiedKeyFingerprints addObject:keyFingerprint];
}

- (void)verifyKeyFingerprints:(NSArray *)keyFingerprints success:(void (^)(NSArray *signers))success failure:(void (^)(NSError *error))failure {
  __weak KBTestKeyRing *blockSelf = self;
  NSArray *s = [keyFingerprints map:^id(NSString *keyFingerprint) {
    return [[KBSigner alloc] initWithKeyFingerprint:keyFingerprint verified:([blockSelf.verifiedKeyFingerprints containsObject:keyFingerprint])];
  }];
  success(s);
}

@end
