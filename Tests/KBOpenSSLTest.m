#import <GRUnit/GRUnit.h>

#import "KBCrypto.h"

#import <GHKit/GHKit.h>

#include <openssl/bn.h>

@interface KBOpenSSLTest : GRTestCase
@end

@implementation KBOpenSSLTest

- (void)testGen {
  BIGNUM *r = BN_new();
  GHDebug(@"Generate prime");
  BN_generate_prime_ex(r, 2048, 0, NULL, NULL, NULL);
  GHDebug(@"Done");
  NSString *decStr = [NSString stringWithUTF8String:BN_bn2dec(r)];
  BN_free(r);
  GHDebug(@"Prime: %@", decStr);
}

@end