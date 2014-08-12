//
//  KBKeygenProgress.m
//  KBCrypto
//
//  Created by Gabriel on 8/11/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBKeygenProgress.h"

#import <ObjectiveSugar/ObjectiveSugar.h>

@interface KBKeygenProgress ()
@property KBKeygenProgressType progressType;
@property float amount;
@property NSString *prime;
@end

@implementation KBKeygenProgress

- (instancetype)initFromJSONDictionary:(NSDictionary *)JSONDictionary {
  if ((self = [super init])) {
    if ([JSONDictionary[@"type"] isEqualToString:@"find_prime_p"]) {
      _progressType = KBKeygenProgressTypeFindCandidateP;
    } else if ([JSONDictionary[@"type"] isEqualToString:@"find_prime_q"]) {
      _progressType = KBKeygenProgressTypeFindCandidateQ;
    } else if ([JSONDictionary[@"type"] isEqualToString:@"testing"]) {
      _progressType = KBKeygenProgressTypeTesting;
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
    case KBKeygenProgressTypeFindCandidateP: {
      return NSStringWithFormat(@"Find Candidate Prime (P): %@", [self primeDescription]);
    }
    case KBKeygenProgressTypeFindCandidateQ: {
      return NSStringWithFormat(@"Find Candidate Prime (Q): %@", [self primeDescription]);
    }
    case KBKeygenProgressTypeTesting: {
      return NSStringWithFormat(@"Testing: %@ (%2.f)%%", [self primeDescription], _amount * 100);
    }
  }
  return @"";
}

@end
