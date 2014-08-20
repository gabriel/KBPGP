//
//  KBPGPKey.m
//  KBCrypto
//
//  Created by Gabriel on 8/14/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBPGPKey.h"

#import <GHKit/GHKit.h>

NSString *NSStringFromKBPGPKeyFlags(KBPGPKeyFlags flags) {
  NSMutableArray *desc = [NSMutableArray array];
  if ((flags & KBPGPKeyFlagsSignData) != 0) [desc addObject:@"Sign"];
  if ((flags & KBPGPKeyFlagsEncryptComm) != 0 || (flags & KBPGPKeyFlagsEncryptStorage) != 0) [desc addObject:@"Encrypt"];
  if ((flags & KBPGPKeyFlagsCertifyKeys) != 0) [desc addObject:@"Certify"];
  if ((flags & KBPGPKeyFlagsAuth) != 0) [desc addObject:@"Auth"];
  if ((flags & KBPGPKeyFlagsShared) != 0) [desc addObject:@"Shared"];
  return [desc componentsJoinedByString:@", "];
}

@implementation KBPGPKey

+ (NSDictionary *)JSONKeyPathsByPropertyKey {
  return @{
           @"fingerprint": @"fingerprint",
           @"bundle": @"bundle",
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

- (void)setSecretKey:(P3SKB *)secretKey {
  _secret = YES;
  _bundle = [secretKey keyBundle];
  _locked = YES;
}

- (KBPGPUserId *)userId {
  if ([_userIds count] == 0) return nil;
  
  for (KBPGPUserId *userId in _userIds) {
    if (userId.primary) return userId;
  }
  return _userIds[0];
}

- (NSArray *)alternateUserIds {
  NSMutableArray *alternateUserIds = [_userIds mutableCopy];
  [alternateUserIds removeObject:[self userId]];
  return alternateUserIds;
}

- (NSString *)userDescription {
  NSMutableArray *desc = [NSMutableArray array];
  KBPGPUserId *userId = [self userId];
  if (userId.userName) [desc addObject:userId.userName];
  if (userId.email) [desc addObject:[NSString stringWithFormat:@"<%@>", userId.email]];
  return [desc componentsJoinedByString:@" "];
}

- (NSString *)typeDescription {
  if (_secret) {
    return @"Secret Key";
  } else {
    return @"Public Key";
  }
}

- (NSComparisonResult)compare:(KBPGPKey *)key2 {
  KBPGPUserId *userId1 = [self userId];
  KBPGPUserId *userId2 = [key2 userId];
  if (userId1.userName) {
    if (!userId2) return NSOrderedAscending;
    return [userId1.userName localizedCaseInsensitiveCompare:userId2.userName];
  } else if (userId2) {
    return NSOrderedDescending;
  }
  return [self.fingerprint caseInsensitiveCompare:key2.fingerprint];
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

- (NSString *)subKeyDescription {
  return [NSString stringWithFormat:@"%@ %d %@ %@", _keyId, (int)_numBits, NSStringFromKBKeyAlgorithm(_algorithm), NSStringFromKBPGPKeyFlags(_flags)];
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

- (NSString *)userIdDescription {
  NSMutableArray *desc = [NSMutableArray array];
  if (_userName) [desc addObject:_userName];
  if (_email) [desc addObject:[NSString stringWithFormat:@"<%@>", _email]];
  return [desc componentsJoinedByString:@" "];
}

@end