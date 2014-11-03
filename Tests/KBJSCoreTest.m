#import <GRUnit/GRUnit.h>

@interface KBJSCoreTest : GRTestCase
@end

#import "KBCrypto.h"
#import "KBJSCore.h"

#import <GHKit/GHKit.h>

@implementation KBJSCoreTest

- (void)testJSRandom {
  KBJSCore *JSCore = [[KBJSCore alloc] initWithQueue:nil exceptionHandler:nil];
  JSContext *context = JSCore.context;
  
  [context evaluateScript:@"var randomHex = jscore.getRandomHexString(32);"];
  NSString *randomHex = [context[@"randomHex"] toString];
  GRAssertEquals([randomHex length], (NSUInteger)64);
}

@end