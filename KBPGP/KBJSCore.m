//
//  KBJSCore.m
//  KBPGP
//
//  Created by Gabriel on 7/1/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBJSCore.h"

#import <GHKit/GHKit.h>
#import <NAChloride/NAChloride.h>
#import <NACrypto/NACrypto.h>
#import "GHBigNum.h"

@implementation KBJSCore

- (instancetype)initWithQueue:(dispatch_queue_t)queue exceptionHandler:(KBJSCoreExceptionHandler)exceptionHandler {
  if ((self = [super init])) {
    _context = [[JSContext alloc] initWithVirtualMachine:[[JSVirtualMachine alloc] init]];
    _context.exceptionHandler = exceptionHandler;

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
    _context[@"jscore"][@"getRandomBase64String"] = ^(JSValue *numBytes) {
      //GHDebug(@"Random hex string of length: %d", [numBytes toUInt32]);
      NSString *data = GHBase64StringFromNSData([NARandom randomData:[numBytes toUInt32]]);
      if (!data) {
        [NSException raise:NSInternalInconsistencyException format:@"No random data available"];
      }
      return data;
    };
    
    _context[@"jscore"][@"generatePrime"] = ^(JSValue *numBits) {
      return [[GHBigNum generatePrime:[numBits toInt32]] decimalString];
    };
    
    _context[@"jscore"][@"bnModPow"] = ^(JSValue *a, JSValue *p, JSValue *m) {
      GHBigNum *ba = [GHBigNum bigNumWithDecimalString:[a toString]];
      GHBigNum *bp = [GHBigNum bigNumWithDecimalString:[p toString]];
      GHBigNum *bm = [GHBigNum bigNumWithDecimalString:[m toString]];
      return [[GHBigNum modPow:ba p:bp m:bm] decimalString];
    };
    
    _context[@"jscore"][@"bnModInverse"] = ^(JSValue *a, JSValue *m) {
      GHBigNum *ba = [GHBigNum bigNumWithDecimalString:[a toString]];
      GHBigNum *bm = [GHBigNum bigNumWithDecimalString:[m toString]];
      return [[GHBigNum modInverse:ba m:bm] decimalString];
    };
  }
  return self;
}

- (BOOL)exists:(id)path {
  NSString *resourcePath = [[NSBundle mainBundle] pathForResource:[path stringByDeletingPathExtension] ofType:[path pathExtension]];
  return !!resourcePath;
}

- (NSString *)readFile:(NSString *)path {
  NSString *resourcePath = [[NSBundle mainBundle] pathForResource:[path stringByDeletingPathExtension] ofType:[path pathExtension]];
  NSString *content = [NSString stringWithContentsOfFile:resourcePath encoding:NSUTF8StringEncoding error:NULL];
  //+ (NSData *)HMACForKey:(NSData *)key data:(NSData *)data algorithm:(NAHMACAlgorithm)algorithm;

  GHDebug(@"JSCore content:%@, %d", path, (int)[content length]);
  return content;
}

- (id)exec:(NSString *)js {
  if (!js) return nil;
  return [[_context evaluateScript:js] toObject];
}

- (void)load:(NSString *)path {
  [self exec:[self readFile:path]];
}

- (NSString *)randomHexString:(NSUInteger)numBytes {
  return [[NARandom randomData:numBytes] na_hexString];
}

@end
