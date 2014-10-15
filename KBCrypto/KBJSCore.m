//
//  KBJSCore.m
//  KBCrypto
//
//  Created by Gabriel on 7/1/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBJSCore.h"

#import <GHKit/GHKit.h>
#import <NAChloride/NAChloride.h>

@implementation KBJSCore

- (instancetype)initWithQueue:(dispatch_queue_t)queue {
  if ((self = [super init])) {
    _context = [[JSContext alloc] initWithVirtualMachine:[[JSVirtualMachine alloc] init]];
    _context.exceptionHandler = ^(JSContext *context, JSValue *exception) {
      id obj = [exception toObject];
      GHDebug(@"Exception: %@, %@", [exception description], obj);
      [NSException raise:NSGenericException format:@"JS Exception"];
    };

    _context[@"console"] = @{};
    _context[@"console"][@"log"] = ^(id obj) {
      GHDebug(@"Console: %@", obj);
    };
    _context[@"console"][@"warn"] = ^(id obj) {
      GHErr(@"Warning: %@", obj);
    };
    _context[@"console"][@"error"] = ^(id obj) {
      GHErr(@"Error: %@", obj);
    };
    _context[@"alert"] = ^(NSString *msg) {
      GHDebug(@"Alert: %@", msg);
    };
    
    _context[@"document"] = @{};
    _context[@"document"][@"write"] = ^(NSString *msg) {
      GHDebug(@"Document write: %@", msg);
    };
    //__block NSInteger count = 0;
    _context[@"setTimeout"] = ^(JSValue *function, JSValue *timeout) {
      int64_t time = (int64_t)([timeout toInt32] * NSEC_PER_MSEC);
      //GHDebug(@"%d ms", (int)[timeout toInt32]);
      if (time < 10) {
        dispatch_async(queue, ^{
          [function callWithArguments:@[]];
        });
      } else {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, time), queue, ^{
          [function callWithArguments:@[]];
        });
      }
    };

    _context[@"jscore"] = @{};
    _context[@"jscore"][@"getRandomHexString"] = ^(JSValue *numBytes) {
      //GHDebug(@"Random hex string of length: %d", [numBytes toUInt32]);
      NSError *error = nil;
      NSString *hexString = [[NARandom randomData:[numBytes toUInt32] error:&error] na_hexString];
      if (!hexString) {
        [NSException raise:NSInternalInconsistencyException format:@"No random data available"];
      }
      return hexString;
    };
  }
  return self;
}

- (BOOL)exists:(id)path {
  NSString *resourcePath = [[NSBundle mainBundle] pathForResource:[path stringByDeletingPathExtension] ofType:[path pathExtension]];
  return !!resourcePath;
}

- (NSString *)readFile:(NSString *)path digest:(NSString *)digest {
  NSString *resourcePath = [[NSBundle mainBundle] pathForResource:[path stringByDeletingPathExtension] ofType:[path pathExtension]];
  NSString *content = [NSString stringWithContentsOfFile:resourcePath encoding:NSUTF8StringEncoding error:NULL];
  //+ (NSData *)HMACForKey:(NSData *)key data:(NSData *)data algorithm:(NAHMACAlgorithm)algorithm;

  NSString *calculatedDigest = [[NADigest digestForData:[content dataUsingEncoding:NSUTF8StringEncoding] algorithm:NADigestAlgorithmSHA2_512] na_hexString];
  if (digest && ![calculatedDigest isEqualToString:digest]) {
    [NSException raise:NSGenericException format:@"Invalid digest"];
    return nil;
  }
  GHDebug(@"JSCore content:%@, %d", path, (int)[content length]);
  return content;
}

- (id)exec:(NSString *)js {
  if (!js) return nil;
  return [[_context evaluateScript:js] toObject];
}

- (void)load:(NSString *)path digest:(NSString *)digest {
  [self exec:[self readFile:path digest:digest]];
}

- (NSString *)randomHexString:(NSUInteger)numBytes {
  return [[NARandom randomData:numBytes error:nil] na_hexString];
}

@end
