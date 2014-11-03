#import <GRUnit/GRUnit.h>

#import "KBCrypto.h"

#import <GHKit/GHKit.h>

@interface KBCryptoReadyTest : GRTestCase
@property KBCrypto *crypto;
@end

@implementation KBCryptoReadyTest

- (void)setUp:(dispatch_block_t)completion {
  _crypto = [[KBCrypto alloc] init];
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