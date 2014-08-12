//
//  KBKeygenProgress.h
//  KBCrypto
//
//  Created by Gabriel on 8/11/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM (NSUInteger, KBKeygenProgressType) {
  KBKeygenProgressTypeFindCandidateP = 1,
  KBKeygenProgressTypeFindCandidateQ,
  KBKeygenProgressTypeTesting
};

@interface KBKeygenProgress : NSObject

@property (readonly) KBKeygenProgressType progressType;
@property (readonly) float amount;
@property (readonly) NSString *prime;

- (instancetype)initFromJSONDictionary:(NSDictionary *)JSONDictionary;

- (NSString *)progressDescription;

@end
