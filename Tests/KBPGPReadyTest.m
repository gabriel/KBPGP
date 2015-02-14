#import <GRUnit/GRUnit.h>

#import "KBPGP.h"

#import <GHKit/GHKit.h>

@interface KBPGPReadyTest : GRTestCase
@property KBPGP *crypto;
@end

@implementation KBPGPReadyTest

- (void)setUp:(dispatch_block_t)completion {
  _crypto = [[KBPGP alloc] init];
  completion();
}

- (void)tearDown {
  _crypto = nil;
}

- (void)testReset:(dispatch_block_t)completion {
  [_crypto resetIfNotReady:^{
    completion();
  }];
}

@end