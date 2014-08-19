//
//  KBCrypto.m
//  KBCrypto
//
//  Created by Gabriel on 7/1/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBCrypto.h"
#import "KBJSCore.h"

#import <GHKit/GHKit.h>
#import <ObjectiveSugar/ObjectiveSugar.h>
#import <NAChloride/NAChloride.h>
#import <TSTripleSec/P3SKB.h>
#import <Mantle/Mantle.h>
#import <libextobjc/EXTScope.h>

@interface KBCrypto ()
//@property dispatch_queue_t queue;
@property KBJSCore *JSCore;
@property id<KBKeyRing> keyRing;
@end

@implementation KBCrypto

- (instancetype)initWithKeyRing:(id<KBKeyRing>)keyRing {
  if ((self = [self init])) {
    _keyRing = keyRing;
  }
  return self;
}

- (void)generateContext {
  KBJSCore *JSCore = [[KBJSCore alloc] init];
  
  [JSCore load:@"keybase.js"];
  [JSCore load:@"keybase-kbpgp-jscore.js"];
  
  _JSCore = JSCore;
  
  _JSCore.context[@"jscore"][@"KeyRing"] = _keyRing;
}

- (void)clearContext {
  _JSCore = nil;
}

- (void)_call:(NSString *)method params:(NSDictionary *)params {
  //_queue = dispatch_queue_create("KBCrypto", NULL);
//  @weakify(self)
//  dispatch_async(_queue, ^{
//    @strongify(self)
//    [self.context[@"jscore"][method] callWithArguments:@[params]];
//  });
  
  if (!_JSCore) [self generateContext];
  [_JSCore.context[@"jscore"][method] callWithArguments:@[params]];
}

- (void)_callback:(dispatch_block_t)callback {
  dispatch_queue_t completionQueue = _completionQueue;
  if (!completionQueue) completionQueue = dispatch_get_main_queue();
  dispatch_async(completionQueue, callback);
}

- (void)encryptText:(NSString *)text keyBundle:(NSString *)keyBundle success:(void (^)(NSString *messageArmored))success failure:(void (^)(NSError *error))failure {
  GHWeakSelf blockSelf = self;
  [self _call:@"encrypt" params:@{@"encrypt_for": keyBundle, @"text": text, @"success": ^(NSString *messageArmored) {
    [blockSelf _callback:^{ success(messageArmored); }];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
  }}];
}

- (void)encryptText:(NSString *)text keyBundle:(NSString *)keyBundle keyBundleForSign:(NSString *)keyBundleForSign passwordForSign:(NSString *)passwordForSign success:(void (^)(NSString *messageArmored))success failure:(void (^)(NSError *error))failure {
  GHWeakSelf blockSelf = self;
  [self _armorBundle:keyBundleForSign password:passwordForSign success:^(NSString *armoredBundleForSign) {
    [blockSelf _call:@"encrypt" params:@{@"encrypt_for": keyBundle, @"sign_with": KBCOrNull(armoredBundleForSign), @"passphrase": KBCOrNull(passwordForSign), @"text": text, @"success": ^(NSString *messageArmored) {
      [blockSelf _callback:^{ success(messageArmored); }];
    }, @"failure": ^(NSString *error) {
      [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
    }}];
  } failure:failure];
}

- (void)signText:(NSString *)text keyBundle:(NSString *)keyBundle password:(NSString *)password success:(void (^)(NSString *clearTextArmored))success failure:(void (^)(NSError *error))failure {
  GHWeakSelf blockSelf = self;
  [self _armorBundle:keyBundle password:password success:^(NSString *armoredBundle) {
    [blockSelf _call:@"sign" params:@{@"sign_with": armoredBundle, @"passphrase": KBCOrNull(password), @"text": text, @"success": ^(NSString *clearTextArmored) {
      [blockSelf _callback:^{ success(clearTextArmored); }];
    }, @"failure": ^(NSString *error) {
      [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
    }}];
  } failure:failure];
}

- (void)_verifyKeyFingerprints:(NSArray *)keyFingerprints plainText:(NSString *)plainText success:(void (^)(NSString *plainText, NSArray *signers))success failure:(void (^)(NSError *error))failure {
  if ([_keyRing respondsToSelector:@selector(verifyKeyFingerprints:success:failure:)]) {
    @weakify(self)
    [_keyRing verifyKeyFingerprints:keyFingerprints success:^(NSArray *signers) {
      @strongify(self)
      [self _callback:^{ success(plainText, signers); }];
    } failure:^(NSError *error) {
      @strongify(self)
      [self _callback:^{ failure(error); }];
    }];
  } else {
    [self _callback:^{ success(plainText, @[]); }];
  }
}

- (void)_armorBundle:(NSString *)bundle password:(NSString *)password success:(void (^)(NSString *armoredBundle))success failure:(void (^)(NSError *error))failure {
  if ([bundle gh_startsWith:@"-----BEGIN PGP"]) {
    success(bundle);
  } else {
    NSData *data = [[NSData alloc] initWithBase64EncodedString:bundle options:0];    
    if (!data) {
      failure(KBCryptoError(@"Not a valid bundle"));
      return;
    }
    
    NSError *error = nil;
    P3SKB *key = [P3SKB P3SKBFromData:data error:&error];
    if (!key) {
      failure(error);
      return;
    }
    
    if (password) {
      if (![key decryptPrivateKeyWithPassword:password error:&error]) {
        failure(error);
        return;
      }
      
      [self armorPrivateKey:key password:password success:^(NSString *encoded) {
        success(encoded);
      } failure:failure];
    } else {
      [self armorPublicKey:key.publicKey success:^(NSString *encoded) {
        success(encoded);
      } failure:failure];
    }
  }
}

- (void)decryptMessageArmored:(NSString *)messageArmored keyBundle:(NSString *)keyBundle password:(NSString *)password success:(void (^)(NSString *plainText, NSArray *signers))success failure:(void (^)(NSError *error))failure {
  @weakify(self)
  [self _armorBundle:keyBundle password:password success:^(NSString *armoredBundle) {
    @strongify(self)
    @weakify(self)
    [self _call:@"decrypt" params:@{@"message_armored": messageArmored, @"decrypt_with": armoredBundle, @"passphrase": KBCOrNull(password), @"success": ^(NSString *plainText, NSArray *keyFingerprints) {
      @strongify(self)
      [self _verifyKeyFingerprints:keyFingerprints plainText:plainText success:success failure:failure];
    }, @"failure": ^(NSString *error) {
      @strongify(self)
      [self _callback:^{ failure(KBCryptoError(error)); }];
    }}];
  } failure:failure];
}

- (void)verifyMessageArmored:(NSString *)messageArmored success:(void (^)(NSString *plainText, NSArray *signers))success failure:(void (^)(NSError *failure))failure {
  @weakify(self)
  [self _call:@"verify" params:@{@"message_armored": messageArmored, @"success": ^(NSString *plainText, NSArray *keyFingerprints) {
    @strongify(self)
    [self _verifyKeyFingerprints:keyFingerprints plainText:plainText success:success failure:failure];
  }, @"failure": ^(NSString *error) {
    @strongify(self)
    [self _callback:^{ failure(KBCryptoError(error)); }];
  }}];
}

- (void)armorPublicKey:(NSData *)data success:(void (^)(NSString *encoded))success failure:(void (^)(NSError *failure))failure {
  @weakify(self)
  [self _call:@"armorPublicKey" params:@{@"data": [data na_hexString], @"success": ^(NSString *encoded) {
    @strongify(self)
    [self _callback:^{ success(encoded); }];
  }, @"failure": ^(NSString *error) {
    @strongify(self)
    [self _callback:^{ failure(KBCryptoError(error)); }];
  }}];
}

- (void)armorPrivateKey:(P3SKB *)secretKey password:(NSString *)password success:(void (^)(NSString *encoded))success failure:(void (^)(NSError *failure))failure {
  NSParameterAssert(secretKey);
  NSError *error = nil;
  NSData *data = [secretKey decryptPrivateKeyWithPassword:password error:&error];
  if (!data) {
    failure(error);
    return;
  }
  
  @weakify(self)
  [self _call:@"armorPrivateKey" params:@{@"data": [data na_hexString], @"passphrase": password, @"success": ^(NSString *encoded) {
    @strongify(self)
    [self _callback:^{ success(encoded); }];
  }, @"failure": ^(NSString *error) {
    @strongify(self)
    [self _callback:^{ failure(KBCryptoError(error)); }];
  }}];
}

- (void)dearmor:(NSString *)armored success:(void (^)(NSData *data))success failure:(void (^)(NSError *failure))failure {
  @weakify(self)
  [self _call:@"dearmor" params:@{@"armored": armored, @"success": ^(NSString *hex) {
    NSData *data = [hex na_dataFromHexString];
    @strongify(self)
    [self _callback:^{ success(data); }];
  }, @"failure": ^(NSString *error) {
    @strongify(self)
    [self _callback:^{ failure(KBCryptoError(error)); }];
  }}];
}

- (void)generateKeyWithUserName:(NSString *)userName userEmail:(NSString *)userEmail keyAlgorithm:(KBKeyAlgorithm)keyAlgorithm password:(NSString *)password progress:(BOOL (^)(KBKeyGenProgress *progress))progress success:(void (^)(P3SKB *privateKey, NSString *publicKeyArmored, NSString *keyFingerprint))success failure:(void (^)(NSError *error))failure {
  
  GHWeakSelf blockSelf = self;
  
  NSMutableDictionary *params = [NSMutableDictionary dictionary];
  if (userEmail) {
    params[@"userid"] = NSStringWithFormat(@"%@ <%@>", userName, userEmail);
  } else {
    params[@"userid"] = userName;
  }
  
  switch (keyAlgorithm) {
    case KBKeyAlgorithmRSA: params[@"algorithm"] = @"rsa"; break;
    case KBKeyAlgorithmECDSA: params[@"algorithm"] = @"ecc"; break;
  }
  
  __block BOOL ok = YES;
  params[@"progress"] = ^BOOL(NSDictionary *progressDict) {
    if (!ok) return NO;
    if (progress) {
      dispatch_async(dispatch_get_main_queue(), ^{
        KBKeyGenProgress *p = [[KBKeyGenProgress alloc] initFromJSONDictionary:progressDict];
        if (progress) {
          ok = progress(p);
        }
      });
    }
    return ok;
  };
  
  params[@"success"] =^(NSString *publicKeyHex, NSString *privateKeyHex, NSString *keyFingerprint) {
    
    NSError *error = nil;
    P3SKB *secretKey = [P3SKB P3SKBWithPrivateKey:[privateKeyHex na_dataFromHexString] password:password publicKey:[publicKeyHex na_dataFromHexString] error:&error];
    if (!secretKey) {
      [blockSelf _callback:^{ failure(error); }];
      return;
    }
    
    [blockSelf armorPublicKey:[secretKey publicKey] success:^(NSString *publicKeyArmored) {
      [blockSelf _callback:^{ success(secretKey, publicKeyArmored, keyFingerprint); }];
    } failure:failure];
  };
  
  params[@"failure"] = ^(NSString *error) {
    [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
  };
  
  // We do not send in a passphrase to generateKeyPair because we will use the P3SKB encrypted format with the passphrase instead.
  [self _call:@"generateKeyPair" params:params];
}

- (void)_PGPKeyForBundle:(NSString *)keyBundle password:(NSString *)password success:(void (^)(KBPGPKey *key))success failure:(void (^)(NSError *error))failure {
  @weakify(self)
  [self _armorBundle:keyBundle password:password success:^(NSString *armoredBundle) {
    [self _call:@"info" params:@{@"armored": armoredBundle, @"success": ^(NSDictionary *dict) {
      NSError *error = nil;
      NSMutableDictionary *mdict = [dict mutableCopy];
      mdict[@"bundle"] = keyBundle;
      KBPGPKey *key = [MTLJSONAdapter modelOfClass:KBPGPKey.class fromJSONDictionary:mdict error:&error];
      if (!key) {
        failure(error);
        return;
      }
      success(key);
    }, @"failure": ^(NSString *error) {
      @strongify(self)
      [self _callback:^{ failure(KBCryptoError(error)); }];
    }}];
  } failure:failure];
}

- (void)PGPKeyForKeyBundle:(NSString *)keyBundle success:(void (^)(KBPGPKey *key))success failure:(void (^)(NSError *error))failure {
  [self _PGPKeyForBundle:keyBundle password:nil success:success failure:failure];
}

- (void)PGPKeyForSecretKey:(P3SKB *)secretKey success:(void (^)(KBPGPKey *key))success failure:(void (^)(NSError *error))failure {
  [self _PGPKeyForBundle:[secretKey keyBundle] password:nil success:^(KBPGPKey *PGPKey) {
    [PGPKey setSecretKey:secretKey];
    success(PGPKey);
  } failure:failure];
}

NSError *KBCryptoError(NSString *message) {
  NSInteger errorCode = KBCryptoErrorCodeDefault;
  if ([message isEqualToString:@"Aborted"]) errorCode = KBCryptoErrorCodeCancelled;
  return [NSError errorWithDomain:@"KBCrypto" code:errorCode userInfo:@{NSLocalizedDescriptionKey:message}];
}

@end
