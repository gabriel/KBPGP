//
//  KBPGPKey.m
//  KBCrypto
//
//  Created by Gabriel on 8/14/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBPGPKey.h"

#import <GHKit/GHKit.h>

@implementation KBPGPKey

+ (NSDictionary *)JSONKeyPathsByPropertyKey {
  return @{
           @"fingerprint": @"fingerprint",
           @"keyId": @"pgp_key_id",
           @"numBits": @"nbits",
           @"flags": @"flags",
           @"algorithm": @"type",
           @"date": @"timestamp",
           @"locked": @"is_locked",
           @"secret": @"has_private",
           @"selfSigned": @"self_signed",
           @"subKeys": @"subkeys",
           @"userIds": @"userids",
           };
}

+ (NSValueTransformer *)dateJSONTransformer {
  return [MTLValueTransformer reversibleTransformerWithForwardBlock:^(id date) {
    return [NSDate gh_parseTimeSinceEpoch:date];
  } reverseBlock:^(NSDate *date) {
    return [NSNumber numberWithUnsignedLongLong:[date timeIntervalSince1970]];
  }];
}

+ (NSValueTransformer *)subKeysJSONTransformer {
  return [NSValueTransformer mtl_JSONArrayTransformerWithModelClass:KBPGPSubKey.class];
}

+ (NSValueTransformer *)userIdsJSONTransformer {
  return [NSValueTransformer mtl_JSONArrayTransformerWithModelClass:KBPGPUserId.class];
}


@end

@implementation KBPGPSubKey

+ (NSDictionary *)JSONKeyPathsByPropertyKey {
  return @{
           @"keyId": @"pgp_key_id",
           @"numBits": @"nbits",
           @"flags": @"flags",
           @"algorithm": @"type",
           @"date": @"timestamp",
           };
}

@end

@implementation KBPGPUserId

+ (NSDictionary *)JSONKeyPathsByPropertyKey {
  return @{
           @"userName": @"username",
           @"email": @"email",
           @"primary": @"primary",
           };
}

@end