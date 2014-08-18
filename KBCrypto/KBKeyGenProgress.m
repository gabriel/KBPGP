//
//  KBKeyGenProgress.m
//  KBCrypto
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
    if ([JSONDictionary[@"type"] isEqualToString:@"find_prime_p"]) {
      _progressType = KBKeyGenProgressTypeFindCandidateP;
    } else if ([JSONDictionary[@"type"] isEqualToString:@"find_prime_q"]) {
      _progressType = KBKeyGenProgressTypeFindCandidateQ;
    } else if ([JSONDictionary[@"type"] isEqualToString:@"testing"]) {
      _progressType = KBKeyGenProgressTypeTesting;
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
    case KBKeyGenProgressTypeFindCandidateP: {
      return NSStringWithFormat(@"Find Candidate Prime (P): %@", [self primeDescription]);
    }
    case KBKeyGenProgressTypeFindCandidateQ: {
      return NSStringWithFormat(@"Find Candidate Prime (Q): %@", [self primeDescription]);
    }
    case KBKeyGenProgressTypeTesting: {
      return NSStringWithFormat(@"Testing: %@ (%2.f)%%", [self primeDescription], _amount * 100);
    }
  }
  return @"";
}

@end
