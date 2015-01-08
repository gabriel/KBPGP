#import <GRUnit/GRUnit.h>

#import "KBCrypto.h"

#import <GHKit/GHKit.h>

@interface KBDetachedTest : GRTestCase
@property KBCrypto *crypto;
@end

@implementation KBDetachedTest

- (NSString *)loadFile:(NSString *)file {
  NSString *path = [[NSBundle mainBundle] pathForResource:[file stringByDeletingPathExtension] ofType:[file pathExtension]];
  NSString *contents = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:NULL];
  NSAssert(contents, @"No contents at file: %@", file);
  return contents;
}

- (void)setUp:(dispatch_block_t)completion {
  if (_crypto) {
    completion();
    return;
  }
  _crypto = [[KBCrypto alloc] init];
  
  //GHWeakSelf blockSelf = self;
  KBPGPKeyRing *keyRing = [[KBPGPKeyRing alloc] init];
  [_crypto setKeyRing:keyRing passwordBlock:nil];
  [_crypto PGPKeyForPublicKeyBundle:[self loadFile:@"user5.asc"] success:^(KBPGPKey *PGPKey1) {
    [keyRing addPGPKey:PGPKey1];
    completion();
  } failure:GRErrorHandler];
}


- (void)test:(dispatch_block_t)completion {
  NSString *armored = [self loadFile:@"sig5.asc"];
  NSMutableString *text = [[[self loadFile:@"msg5.txt"] gh_strip] mutableCopy];
  [text replaceOccurrencesOfString:@"\r\n" withString:@"\n" options:0 range:NSMakeRange(0, text.length)];
  [text replaceOccurrencesOfString:@"\n" withString:@"\r\n" options:0 range:NSMakeRange(0, text.length)];
  [text appendString:@"\r\n"];
  
  [_crypto verifyArmored:armored data:[text dataUsingEncoding:NSUTF8StringEncoding] success:^(KBPGPMessage *PGPMessage) {
    completion();
  } failure:GRErrorHandler];
}

@end
