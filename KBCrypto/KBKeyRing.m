//
//  KBKeyRing.m
//  KBCrypto
//
//  Created by Gabriel on 7/29/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBKeyRing.h"
#import "KBCrypto.h"

#import <ObjectiveSugar/ObjectiveSugar.h>
#import <GHKit/GHKit.h>

@interface KBKeyRing ()
@property NSMutableDictionary *keys;
@end

@implementation KBKeyRing

- (id)init {
  if ((self = [super init])) {
    _keys = [NSMutableDictionary dictionary];
  }
  return self;
}

- (void)addKey:(id<KBKey>)key keyIds:(NSArray *)keyIds capabilities:(KBKeyCapabilities)capabilities {
  for (NSString *keyId in keyIds) {
    NSMutableArray *keys = _keys[[keyId lowercaseString]];
    if (!keys) {
      keys = [NSMutableArray array];
      _keys[keyId] = keys;
    }
    [keys addObject:@{
                      @"key": key,
                      @"capabilities": @(capabilities)
                      }];
  }
}

- (void)lookupKeyIds:(NSArray *)keyIds capabilities:(KBKeyCapabilities)capabilities success:(void (^)(NSArray *keyBundles))success failure:(void (^)(NSError *error))failure {
  NSMutableArray *found = [NSMutableArray array];
  for (NSString *keyId in keyIds) {
    NSArray *keys = _keys[[keyId lowercaseString]];
    if (keys) {
      for (NSDictionary *key in keys) {
        if (([key[@"capabilities"] unsignedIntegerValue] & capabilities) != 0) {
          [found addObject:key[@"key"]];
        }
      }
    }
  }
  
  GHDebug(@"Lookup key ids: %@, %@; %@", keyIds, KBKeyCapabilitiesDescription(capabilities), found);
  
  if ([found count] > 0) {
    success(found);
  } else {
    failure(KBCNSError(-1, NSStringWithFormat(@"No key for ids: %@", keyIds)));
  }
}

@end
