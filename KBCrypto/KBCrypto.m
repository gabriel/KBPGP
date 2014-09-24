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

@interface KBCrypto ()
@property dispatch_queue_t queue;
@property KBJSCore *JSCore;
@property KBCryptoKeyRing *cryptoKeyRing;
@end

typedef void (^KBCryptoJSFailureBlock)(NSString *error);

@implementation KBCrypto

- (instancetype)init {
  if ((self = [super init])) {
    _queue = dispatch_queue_create("KBCrypto", NULL);
  }
  return self;
}

- (BOOL)generateContext {
  KBJSCore *JSCore = [[KBJSCore alloc] init];
  
  @try {
    [JSCore load:@"keybase.js" digest:nil]; //@"9f6490e7ccd0b21dc96d1c0daa53c4d0059b9e85418d16b083f5d91710d133da58bd9cd7449bb059757655c89deb3df9669c594e0de2d260077ceeec7bf37259"];
    [JSCore load:@"keybase-kbpgp-jscore.js" digest:nil]; //@"8e459ad88f25949d594637793cf847ec2c6b67c59820dcfc94cbde99d974e983dd52ce3e42efa1cce41d7e1ebd404756e65d2288117b27f043eff0587bfd71c8"];
  } @catch(NSException *e) {
    return NO;
  }
  
  _JSCore = JSCore;
  _JSCore.completionQueue = _queue;
  
  if (_cryptoKeyRing) {
    _JSCore.context[@"jscore"][@"KeyRing"] = _cryptoKeyRing;
  }
  return YES;
}

- (void)setKeyRing:(id<KBKeyRing>)keyRing passwordBlock:(KBKeyRingPasswordBlock)passwordBlock {
  _cryptoKeyRing = [[KBCryptoKeyRing alloc] initWithKeyRing:keyRing];
  _cryptoKeyRing.passwordBlock = passwordBlock;
  _cryptoKeyRing.completionQueue = _queue;
  if (_JSCore) {
    _JSCore.context[@"jscore"][@"KeyRing"] = _cryptoKeyRing;
  }
}

- (void)clearContext {
  _JSCore = nil;
}

- (void)_call:(NSString *)method params:(NSDictionary *)params {
  if (!_JSCore) {
    BOOL loaded = [self generateContext];
    if (!loaded) {
      [self _callback:^{
        KBCryptoJSFailureBlock failureBlock = params[@"failure"];
        failureBlock(@"Can't load cypto library");
      }];
    }
  }
  
  GHWeakSelf blockSelf = self;
  [self _call:^{
    [blockSelf.JSCore.context[@"jscore"][method] callWithArguments:@[params]];
  }];
}

- (void)_call:(dispatch_block_t)block {
  dispatch_async(_queue, block);
}

- (void)_callback:(dispatch_block_t)callback {
  dispatch_queue_t completionQueue = _completionQueue;
  if (!completionQueue) completionQueue = dispatch_get_main_queue();
  dispatch_async(completionQueue, callback);
}

- (void)encryptText:(NSString *)text keyBundles:(NSArray *)keyBundles success:(void (^)(NSString *messageArmored))success failure:(KBCyptoErrorBlock)failure {
  GHWeakSelf blockSelf = self;
  [self _call:@"encrypt" params:@{@"encrypt_for": keyBundles, @"text": text, @"success": ^(NSString *messageArmored) {
    [blockSelf _callback:^{ success(messageArmored); }];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
  }}];
}

- (void)encryptText:(NSString *)text keyBundles:(NSArray *)keyBundles keyBundleForSign:(NSString *)keyBundleForSign passwordForSign:(NSString *)passwordForSign success:(void (^)(NSString *messageArmored))success failure:(KBCyptoErrorBlock)failure {
  GHWeakSelf blockSelf = self;
  [self _armorBundle:keyBundleForSign password:passwordForSign success:^(NSString *armoredBundleForSign, BOOL isSecret) {
    [blockSelf _call:@"encrypt" params:@{@"encrypt_for": keyBundles, @"sign_with": KBCOrNull(armoredBundleForSign), @"passphrase": KBCOrNull(passwordForSign), @"text": text, @"success": ^(NSString *messageArmored) {
      [blockSelf _callback:^{ success(messageArmored); }];
    }, @"failure": ^(NSString *error) {
      [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
    }}];
  } failure:failure];
}

- (void)signText:(NSString *)text keyBundle:(NSString *)keyBundle password:(NSString *)password success:(void (^)(NSString *armoredSignature))success failure:(KBCyptoErrorBlock)failure {
  GHWeakSelf blockSelf = self;
  [self _armorBundle:keyBundle password:password success:^(NSString *armoredBundle, BOOL isSecret) {
    [blockSelf _call:@"sign" params:@{@"sign_with": armoredBundle, @"passphrase": KBCOrNull(password), @"text": text, @"success": ^(NSString *resultString) {
      [blockSelf _callback:^{ success(resultString); }];
    }, @"failure": ^(NSString *error) {
      [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
    }}];
  } failure:failure];
}

- (void)_armorBundle:(NSString *)bundle password:(NSString *)password success:(void (^)(NSString *armoredBundle, BOOL isSecret))success failure:(KBCyptoErrorBlock)failure {
  if ([bundle gh_startsWith:@"-----BEGIN PGP PRIVATE KEY"]) {
    success(bundle, YES);
  } else if ([bundle gh_startsWith:@"-----BEGIN PGP PUBLIC KEY"]) {
    success(bundle, NO);
  } else {
    [self _armoredForSecretKeyBundle:bundle password:password success:^(NSString *armoredBundle) {
      success(armoredBundle, YES);
    } failure:failure];
  }
}

- (void)_armoredForSecretKeyBundle:(NSString *)bundle password:(NSString *)password success:(void (^)(NSString *armoredBundle))success failure:(KBCyptoErrorBlock)failure {
  if (!bundle) {
    failure(KBCryptoError(@"Not a valid bundle"));
    return;
  }
  
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
    [self armoredKeyBundleFromSecretKey:key password:password keyBundlePassword:password success:^(NSString *encoded) {
      success(encoded);
    } failure:failure];
  } else {
    [self armoredKeyBundleFromPublicKey:key.publicKey success:^(NSString *encoded) {
      success(encoded);
    } failure:failure];
  }
}

- (void)_parseFetches:(NSArray *)fetches verifyKeyIds:(NSMutableArray *)verifyKeyIds decryptKeyIds:(NSMutableArray *)decryptKeyIds {
  for (NSDictionary *fetch in fetches) {
    NSArray *keyIds = fetch[@"key_ids"];
    if ([keyIds count] == 0) continue;
    KBKeyCapabilities capabilities = [fetch[@"ops"] integerValue];
    if (KBHasCapabilities(capabilities, KBKeyCapabilitiesVerify)) [verifyKeyIds addObjectsFromArray:keyIds];
    if (KBHasCapabilities(capabilities, KBKeyCapabilitiesDecrypt)) [decryptKeyIds addObjectsFromArray:keyIds];
  }
}

- (void)_parseMessage:(NSData *)data messageArmored:(NSString *)messageArmored keyFingerprints:(NSArray *)keyFingerprints warnings:(NSArray *)warnings fetches:(NSArray *)fetches success:(KBCryptoUnboxBlock)success failure:(KBCyptoErrorBlock)failure {
  GHWeakSelf blockSelf = self;
  
  NSMutableArray *verifyKeyIds = [NSMutableArray array];
  NSMutableArray *decryptKeyIds = [NSMutableArray array];
  [self _parseFetches:fetches verifyKeyIds:verifyKeyIds decryptKeyIds:decryptKeyIds];
  
  [_cryptoKeyRing verifyKeyFingerprints:keyFingerprints success:^(NSArray *signers) {
    KBPGPMessage *message = [KBPGPMessage messageWithVerifyKeyIds:verifyKeyIds decryptKeyIds:decryptKeyIds bundle:messageArmored data:data signers:signers warnings:warnings];
    [blockSelf _callback:^{ success(message); }];
  } failure:^(NSError *error) {
    [blockSelf _callback:^{ failure(error); }];
  }];
}

- (void)decryptMessageArmored:(NSString *)messageArmored keyBundle:(NSString *)keyBundle password:(NSString *)password success:(KBCryptoUnboxBlock)success failure:(KBCyptoErrorBlock)failure {
  GHWeakSelf blockSelf = self;
  [self _armorBundle:keyBundle password:password success:^(NSString *armoredBundle, BOOL isSecret) {
    [blockSelf _call:@"decrypt" params:@{@"message_armored": messageArmored, @"decrypt_with": armoredBundle, @"passphrase": KBCOrNull(password), @"success": ^(NSString *hexData, NSArray *keyFingerprints, NSArray *warnings, NSArray *fetches) {
      [blockSelf _parseMessage:[hexData na_dataFromHexString] messageArmored:messageArmored keyFingerprints:keyFingerprints warnings:warnings fetches:fetches success:success failure:failure];
    }, @"failure": ^(NSString *error) {
      [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
    }}];
  } failure:failure];
}

- (void)verifyMessageArmored:(NSString *)messageArmored success:(KBCryptoUnboxBlock)success failure:(void (^)(NSError *failure))failure {
  GHWeakSelf blockSelf = self;
  [self _call:@"verify" params:@{@"message_armored": messageArmored, @"success": ^(NSString *hexData, NSArray *keyFingerprints, NSArray *warnings, NSArray *fetches) {
    [blockSelf _parseMessage:[hexData na_dataFromHexString] messageArmored:messageArmored keyFingerprints:keyFingerprints warnings:warnings fetches:fetches success:success failure:failure];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
  }}];
}

- (void)unboxMessageArmored:(NSString *)messageArmored success:(KBCryptoUnboxBlock)success failure:(void (^)(NSError *failure))failure {
  GHWeakSelf blockSelf = self;
  [self _call:@"unbox" params:@{@"message_armored": messageArmored, @"success": ^(NSString *hexData, NSArray *keyFingerprints, NSArray *warnings, NSArray *fetches) {
    [blockSelf _parseMessage:[hexData na_dataFromHexString] messageArmored:messageArmored keyFingerprints:keyFingerprints warnings:warnings fetches:fetches success:success failure:failure];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
  }}];
}

- (void)armoredKeyBundleFromPublicKey:(NSData *)data success:(void (^)(NSString *encoded))success failure:(void (^)(NSError *failure))failure {
  GHWeakSelf blockSelf = self;
  [self _call:@"armorPublicKey" params:@{@"data": [data na_hexString], @"success": ^(NSString *encoded) {
    [blockSelf _callback:^{ success(encoded); }];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
  }}];
}

- (void)armoredKeyBundleFromSecretKey:(P3SKB *)secretKey password:(NSString *)password keyBundlePassword:(NSString *)keyBundlePassword success:(void (^)(NSString *encoded))success failure:(void (^)(NSError *failure))failure {
  NSParameterAssert(secretKey);
  
  GHWeakSelf blockSelf = self;
  [self _call:^{
    NSError *error = nil;
    NSData *data = [secretKey decryptPrivateKeyWithPassword:password error:&error];
    if (!data) {
      [blockSelf _callback: ^{ failure(error); }];
      return;
    }
    
    [blockSelf _call:@"armorPrivateKey" params:@{@"data": [data na_hexString], @"passphrase": KBCOrNull(keyBundlePassword), @"success": ^(NSString *encoded) {
      [blockSelf _callback:^{ success(encoded); }];
    }, @"failure": ^(NSString *error) {
      [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
    }}];
  }];
}

- (void)armoredKeyBundleFromPGPKey:(KBPGPKey *)PGPKey password:(NSString *)password keyBundlePassword:(NSString *)keyBundlePassword success:(void (^)(NSString *encoded))success failure:(KBCyptoErrorBlock)failure {
  if (PGPKey.secretKey) {
    [self armoredKeyBundleFromSecretKey:PGPKey.secretKey password:password keyBundlePassword:keyBundlePassword success:success failure:failure];
  } else {
    NSAssert(PGPKey.publicKeyBundle, @"No bundle");
    [self _callback:^{ success(PGPKey.publicKeyBundle); }];
  }
}

- (void)armoredPublicKeyBundleFromKeyBundle:(NSString *)keyBundle success:(void (^)(NSString *keyBundle))success failure:(KBCyptoErrorBlock)failure {
  if ([keyBundle gh_startsWith:@"-----BEGIN PGP PUBLIC KEY"]) {
    [self _callback:^{ success(keyBundle); }];
  } else if ([keyBundle gh_startsWith:@"-----BEGIN PGP PRIVATE KEY"]) {
    GHWeakSelf blockSelf = self;
    [self _call:@"exportPublicKey" params:@{@"armored": keyBundle, @"success": ^(NSString *encoded) {
      [blockSelf _callback:^{ success(encoded); }];
    }, @"failure": ^(NSString *error) {
      [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
    }}];
  } else {
    [self _armoredForSecretKeyBundle:keyBundle password:nil success:success failure:failure];
  }
}

- (void)dearmor:(NSString *)armored success:(void (^)(NSData *data))success failure:(void (^)(NSError *failure))failure {
  GHWeakSelf blockSelf = self;
  [self _call:@"dearmor" params:@{@"armored": armored, @"success": ^(NSString *hex) {
    NSData *data = [hex na_dataFromHexString];
    [blockSelf _callback:^{ success(data); }];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
  }}];
}

- (void)generateKeyWithUserName:(NSString *)userName userEmail:(NSString *)userEmail keyAlgorithm:(KBKeyAlgorithm)keyAlgorithm password:(NSString *)password progress:(BOOL (^)(KBKeyGenProgress *progress))progress success:(void (^)(P3SKB *privateKey, NSString *publicKeyArmored, NSString *keyFingerprint))success failure:(KBCyptoErrorBlock)failure {
  
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
    default:
      [NSException raise:NSInvalidArgumentException format:@"Algorithm is unsupported."];
      break;
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
    
    [blockSelf armoredKeyBundleFromPublicKey:[secretKey publicKey] success:^(NSString *publicKeyArmored) {
      [blockSelf _callback:^{ success(secretKey, publicKeyArmored, keyFingerprint); }];
    } failure:failure];
  };
  
  params[@"failure"] = ^(NSString *error) {
    [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
  };
  
  // We do not send in a passphrase to generateKeyPair because we will use the P3SKB encrypted format with the passphrase instead.
  [self _call:@"generateKeyPair" params:params];
}

- (void)_PGPKeyForBundle:(NSString *)keyBundle keyBundlePassword:(NSString *)keyBundlePassword password:(NSString *)password success:(void (^)(KBPGPKey *key))success failure:(KBCyptoErrorBlock)failure {
  GHWeakSelf blockSelf = self;
  [self _armorBundle:keyBundle password:password success:^(NSString *armoredBundle, BOOL isSecret) {
    [blockSelf _call:@"info" params:@{@"armored": armoredBundle, @"success": ^(NSDictionary *dict, NSString *publicKeyHex) {
      NSError *error = nil;
      
      NSMutableDictionary *infoDict = [dict mutableCopy];
      infoDict[@"is_secret"] = @(isSecret);
      
      KBPGPKey *key = [MTLJSONAdapter modelOfClass:KBPGPKey.class fromJSONDictionary:infoDict error:&error];
      if (!key) {
        [blockSelf _callback:^{ failure(error); }];
        return;
      }
      
      // If secret key, lets set the bundle as the P3SKB data which is more secure
      if (isSecret && keyBundlePassword) {
        // Clear bundle password, we will encrypt P3SKB with that password right after
        [blockSelf setPasswordForArmoredKeyBundle:armoredBundle previousPassword:keyBundlePassword password:nil success:^(NSString *keyBundleNoPassword) {
          [blockSelf dearmor:keyBundleNoPassword success:^(NSData *data) {
            P3SKB *secretKey = [P3SKB P3SKBWithPrivateKey:data password:password publicKey:[publicKeyHex na_dataFromHexString] error:nil];
            if (!secretKey) {
              [blockSelf _callback:^{ failure(KBCryptoError(@"Couldn't dearmor")); }];
              return;
            }
            [key setSecretKey:secretKey];
            
            [blockSelf _callback:^{ success(key); }];
          } failure:failure];
        } failure:failure];
      } else {
        [blockSelf _callback:^{ success(key); }];
      }
    }, @"failure": ^(NSString *error) {
      [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
    }}];
  } failure:failure];
}

- (void)PGPKeyForKeyBundle:(NSString *)keyBundle keyBundlePassword:(NSString *)keyBundlePassword password:(NSString *)password success:(void (^)(KBPGPKey *PGPKey))success failure:(KBCyptoErrorBlock)failure {
  [self _PGPKeyForBundle:keyBundle keyBundlePassword:keyBundlePassword password:password success:success failure:failure];
}

- (void)PGPKeyForSecretKey:(P3SKB *)secretKey success:(void (^)(KBPGPKey *PGPKey))success failure:(KBCyptoErrorBlock)failure {
  // Password here is nil because we use the public key to generate info
  [self _PGPKeyForBundle:[secretKey keyBundle] keyBundlePassword:nil password:nil success:^(KBPGPKey *PGPKey) {
    [PGPKey setSecretKey:secretKey];
    success(PGPKey); // ok to not have this in a _callback
  } failure:failure];
}

- (void)setPasswordForArmoredKeyBundle:(NSString *)armoredKeyBundle previousPassword:(NSString *)previousPassword password:(NSString *)password success:(void (^)(NSString *keyBundle))success failure:(KBCyptoErrorBlock)failure {
  GHWeakSelf blockSelf = self;
  [self _call:@"setPassword" params:@{@"armored": armoredKeyBundle, @"previous": KBCOrNull(previousPassword), @"passphrase": KBCOrNull(password), @"success": ^(NSString *keyBundle) {
    [blockSelf _callback:^{ success(keyBundle); }];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
  }}];
}

- (void)checkPasswordForArmoredKeyBundle:(NSString *)armoredKeyBundle password:(NSString *)password success:(dispatch_block_t)success failure:(KBCyptoErrorBlock)failure {
  GHWeakSelf blockSelf = self;
  [self _call:@"checkPassword" params:@{@"armored": armoredKeyBundle, @"passphrase": KBCOrNull(password), @"success": ^(NSString *keyBundle) {
    [blockSelf _callback:^{ success(); }];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
  }}];
}

NSError *KBCryptoError(NSString *message) {
  NSInteger errorCode = KBCryptoErrorCodeDefault;
  if ([message isEqualToString:@"Aborted"]) errorCode = KBCryptoErrorCodeCancelled;
  return [NSError errorWithDomain:@"KBCrypto" code:errorCode userInfo:@{NSLocalizedDescriptionKey:message}];
}

@end
