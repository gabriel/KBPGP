//
//  KBKey.m
//  KBCrypto
//
//  Created by Gabriel on 7/31/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBKey.h"

#import <GHKit/GHKit.h>

NSString *KBKeyIdFromFingerprint(NSString *fingerprint) {
  if (!fingerprint) return nil;
  if ([fingerprint length] < 16) return fingerprint;
  return [[fingerprint substringFromIndex:[fingerprint length] - 16] lowercaseString];
}

NSString *KBKeyDisplayDescription(NSString *fingerprint) {
  if ([fingerprint length] < 16) return fingerprint;
  NSString *str = [[fingerprint substringFromIndex:[fingerprint length] - 16] lowercaseString];
  return [@[[str substringWithRange:NSMakeRange(0, 4)],
            [str substringWithRange:NSMakeRange(4, 4)],
            [str substringWithRange:NSMakeRange(8, 4)],
            [str substringWithRange:NSMakeRange(12, 4)]] componentsJoinedByString:@" "];

}

NSString *KBKeyCapabilitiesDescription(KBKeyCapabilities capabilities) {
  NSMutableArray *desc = [NSMutableArray array];
  if ((capabilities & KBKeyCapabilitiesDecrypt) != 0) [desc addObject:@"Decrypt"];
  if ((capabilities & KBKeyCapabilitiesEncrypt) != 0) [desc addObject:@"Encrypt"];
  if ((capabilities & KBKeyCapabilitiesSign) != 0) [desc addObject:@"Sign"];
  if ((capabilities & KBKeyCapabilitiesVerify) != 0) [desc addObject:@"Verify"];
  return [desc componentsJoinedByString:@", "];
}


