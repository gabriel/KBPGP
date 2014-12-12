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
  
  [context evaluateScript:@"var random = jscore.getRandomBase64String(32);"];
  NSString *random = [context[@"random"] toString];
  GRAssertEquals([random length], (NSUInteger)44);
}

@end