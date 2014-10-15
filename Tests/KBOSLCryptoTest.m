#import <GRUnit/GRUnit.h>

#import "KBCrypto.h"

#import <GHKit/GHKit.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

@interface KBOSLCryptoTest : GRTestCase
@end

@implementation KBOSLCryptoTest

- (void)testGen {
  RSA *keypair = RSA_generate_key(2048, 3, NULL, NULL);
}

@end