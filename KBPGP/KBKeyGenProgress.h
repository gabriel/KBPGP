//
//  KBKeyGenProgress.h
//  KBPGP
//
//  Created by Gabriel on 8/11/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM (NSUInteger, KBKeyGenProgressType) {
  KBKeyGenProgressTypePrimeP = 1,
  KBKeyGenProgressTypePrimeQ,
  KBKeyGenProgressTypeTestingPrime
};

@interface KBKeyGenProgress : NSObject

@property (readonly) KBKeyGenProgressType progressType;
@property (readonly) float amount;
@property (readonly) NSString *prime;

- (instancetype)initFromJSONDictionary:(NSDictionary *)JSONDictionary;

- (NSString *)progressDescription;

@end
