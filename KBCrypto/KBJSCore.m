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
#import <libextobjc/EXTScope.h>

@interface KBJSCore ()
@end

@implementation KBJSCore

- (instancetype)initWithContext:(JSContext *)context {
  if ((self = [super init])) {
    _context = context;
    [_context evaluateScript:@"var console = {}"];
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
    
    [_context evaluateScript:@"var document = {}"];
    _context[@"document"][@"write"] = ^(NSString *msg) {
      GHDebug(@"Document write: %@", msg);
    };
    
    _context[@"setTimeout"] = ^(JSValue *function, JSValue *timeout) {
      int64_t time = (int64_t)([timeout toInt32] * NSEC_PER_MSEC);
      //GHDebug(@"Time: %d", [timeout toInt32]);
      dispatch_after(dispatch_time(DISPATCH_TIME_NOW, time), dispatch_get_current_queue(), ^{
        [function callWithArguments:@[]];
      });
    };
    
//    _context[@"process"] = @{};
//    _context[@"process"][@"nextTick"] = ^(JSValue *function) {
//      @strongify(self)
//      dispatch_queue_t queue = self.queue;
//      GHDebug(@"Next tick");
//      dispatch_async(queue, ^{
//        [function callWithArguments:@[]];
//      });
//    };
    
    [_context evaluateScript:@"var jscore = jscore || {}"];
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

- (void)setUp {
  
}

- (BOOL)exists:(id)path {
  NSString *resourcePath = [[NSBundle mainBundle] pathForResource:[path stringByDeletingPathExtension] ofType:[path pathExtension]];
  return !!resourcePath;
}

- (NSString *)readFile:(NSString *)path {
  NSString *resourcePath = [[NSBundle mainBundle] pathForResource:[path stringByDeletingPathExtension] ofType:[path pathExtension]];
  NSString *content = [NSString stringWithContentsOfFile:resourcePath encoding:NSUTF8StringEncoding error:NULL];
  return content;
}

- (id)exec:(NSString *)js {
  NSParameterAssert(js);
  return [[_context evaluateScript:js] toObject];
}

- (void)load:(NSString *)path {
  [self exec:[self readFile:path]];
}

- (NSString *)randomHexString:(NSUInteger)numBytes {
  return [[NARandom randomData:numBytes error:nil] na_hexString];
}

@end
