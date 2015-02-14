//
//  KBKeyGenProgress.m
//  KBPGP
//
//  Created by Gabriel on 8/11/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBKeyGenProgress.h"

#import <ObjectiveSugar/ObjectiveSugar.h>

@interface KBKeyGenProgress ()
@property KBKeyGenProgressType progressType;
@property float amount;
@property NSString *prime;
@end

@implementation KBKeyGenProgress

- (instancetype)initFromJSONDictionary:(NSDictionary *)JSONDictionary {
  if ((self = [super init])) {
    if ([JSONDictionary[@"type"] isEqualToString:@"prime_p"]) {
      _progressType = KBKeyGenProgressTypePrimeP;
    } else if ([JSONDictionary[@"type"] isEqualToString:@"prime_q"]) {
      _progressType = KBKeyGenProgressTypePrimeQ;
    } else if ([JSONDictionary[@"type"] isEqualToString:@"testing"]) {
      _progressType = KBKeyGenProgressTypeTestingPrime;
    } else {
      NSAssert(NO, @"Invalid type");
    }
    
    _prime = JSONDictionary[@"prime"];
    _amount = [JSONDictionary[@"amount"] floatValue];
  }
  return self;
}

- (NSString *)primeDescription {
  if (!_prime) return @"";
  return NSStringWithFormat(@"...%@", [_prime substringFromIndex:[_prime length] - 3]);
}

- (NSString *)progressDescription {
  switch (_progressType) {
    case KBKeyGenProgressTypePrimeP: {
      return @"Found Prime (P)...";
    }
    case KBKeyGenProgressTypePrimeQ: {
      return @"Found Prime (Q)...";
    }
    case KBKeyGenProgressTypeTestingPrime: {
      return NSStringWithFormat(@"Testing: %@ (%2.f)%%", [self primeDescription], _amount * 100);
    }
  }
  return @"";
}

@end
