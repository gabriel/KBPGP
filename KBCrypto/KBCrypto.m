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
#import <TSTripleSec/TSTripleSec.h>
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
    _queue = dispatch_queue_create("KBCrypto", DISPATCH_QUEUE_SERIAL);
    //dispatch_queue_t q = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0);
    //dispatch_set_target_queue(_queue, q);
    
    [self generateContext];
  }
  return self;
}

- (void)generateContext {
  KBJSCore *JSCore = [[KBJSCore alloc] initWithQueue:_queue exceptionHandler:^(JSContext *context, JSValue *exception) {
    id obj = [exception toObject];
    GHDebug(@"Error: %@, %@", [exception description], obj);
    [NSException raise:NSGenericException format:@"JS Exception: %@, %@", [exception description], obj];
  }];
  
  [JSCore load:@"keybase.js" digest:nil]; //@"9f6490e7ccd0b21dc96d1c0daa53c4d0059b9e85418d16b083f5d91710d133da58bd9cd7449bb059757655c89deb3df9669c594e0de2d260077ceeec7bf37259"];
  [JSCore load:@"keybase-kbpgp-jscore.js" digest:nil]; //@"8e459ad88f25949d594637793cf847ec2c6b67c59820dcfc94cbde99d974e983dd52ce3e42efa1cce41d7e1ebd404756e65d2288117b27f043eff0587bfd71c8"];
  
  _JSCore = JSCore;
}

- (void)clearContext {
  _JSCore = nil;
}

- (void)setKeyRing:(id<KBKeyRing>)keyRing passwordBlock:(KBKeyRingPasswordBlock)passwordBlock {
  _cryptoKeyRing = [[KBCryptoKeyRing alloc] initWithKeyRing:keyRing];
  _cryptoKeyRing.passwordBlock = passwordBlock;
  _cryptoKeyRing.completionQueue = _queue;
  _JSCore.context[@"jscore"][@"KeyRing"] = _cryptoKeyRing;
}

- (void)_call:(NSString *)method params:(NSDictionary *)params {
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

- (void)isReady:(void (^)(BOOL ready))completion {
  [self _call:@"ready" params:@{@"cb": ^(BOOL b) {
    completion(b);
  }}];
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
  [blockSelf _call:@"encrypt" params:@{@"encrypt_for": keyBundles, @"sign_with": KBCOrNull(keyBundleForSign), @"passphrase": KBCOrNull(passwordForSign), @"text": text, @"success": ^(NSString *messageArmored) {
    [blockSelf _callback:^{ success(messageArmored); }];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
  }}];
}

- (void)signText:(NSString *)text keyBundle:(NSString *)keyBundle password:(NSString *)password success:(void (^)(NSString *armoredSignature))success failure:(KBCyptoErrorBlock)failure {
  GHWeakSelf blockSelf = self;
  [blockSelf _call:@"sign" params:@{@"sign_with": keyBundle, @"passphrase": KBCOrNull(password), @"text": text, @"success": ^(NSString *resultString) {
    [blockSelf _callback:^{ success(resultString); }];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
  }}];
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
  [blockSelf _call:@"decrypt" params:@{@"message_armored": messageArmored, @"decrypt_with": keyBundle, @"passphrase": KBCOrNull(password), @"success": ^(NSString *hexData, NSArray *keyFingerprints, NSArray *warnings, NSArray *fetches) {
    [blockSelf _parseMessage:[hexData na_dataFromHexString] messageArmored:messageArmored keyFingerprints:keyFingerprints warnings:warnings fetches:fetches success:success failure:failure];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
  }}];
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
    
    GHDebug(@"Armor private key");
    [blockSelf _call:@"armorPrivateKey" params:@{@"data": [data na_hexString], @"passphrase": KBCOrNull(keyBundlePassword), @"success": ^(NSString *encoded) {
      GHDebug(@"Armored");
      [blockSelf _callback:^{ success(encoded); }];
    }, @"failure": ^(NSString *error) {
      [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
    }}];
  }];
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

- (void)setUserIds:(NSArray *)userIds PGPKey:(KBPGPKey *)PGPKey password:(NSString *)password success:(void (^)(KBPGPKey *PGPKey))success failure:(KBCyptoErrorBlock)failure {
  GHWeakSelf blockSelf = self;
  
  userIds = [userIds map:^id(KBPGPUserId *userId) { return [userId RFC822]; }];
  NSString *privateKeyBundle = [PGPKey decryptSecretKeyArmoredWithPassword:password error:nil];
  [self _call:@"setUserIds" params:@{@"armored": privateKeyBundle, @"passphrase": KBCOrNull(password), @"userids": userIds, @"success": ^(NSDictionary *dict, NSString *publicKeyArmored, NSString *publicKeyHex, NSString *privateKeyArmoredNoPassword, NSString *privateKeyHexNoPassword) {
    [self _PGPKeyForExport:dict publicKeyArmored:publicKeyArmored publicKeyHex:publicKeyHex privateKeyArmoredNoPassword:privateKeyArmoredNoPassword privateKeyHexNoPassword:privateKeyHexNoPassword password:password success:success failure:failure];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
  }}];
}

- (void)generateKeyWithUserIds:(NSArray */*of KBPGPUserId*/)userIds keyAlgorithm:(KBKeyAlgorithm)keyAlgorithm password:(NSString *)password progress:(BOOL (^)(KBKeyGenProgress *progress))progress success:(void (^)(KBPGPKey *PGPKey))success failure:(KBCyptoErrorBlock)failure {
  
  GHWeakSelf blockSelf = self;
  
  NSMutableDictionary *params = [NSMutableDictionary dictionary];
  params[@"userids"] = [userIds map:^id(KBPGPUserId *userId) { return [userId RFC822]; }];

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
  
  params[@"success"] = ^(NSDictionary *dict, NSString *publicKeyArmored, NSString *publicKeyHex, NSString *privateKeyArmoredNoPassword, NSString *privateKeyHexNoPassword) {
    [self _PGPKeyForExport:dict publicKeyArmored:publicKeyArmored publicKeyHex:publicKeyHex privateKeyArmoredNoPassword:privateKeyArmoredNoPassword privateKeyHexNoPassword:privateKeyHexNoPassword password:password success:success failure:failure];
  };
  
  params[@"failure"] = ^(NSString *error) {
    [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
  };
  
  // We do not send in a passphrase to generateKeyPair because we will use the P3SKB encrypted format with the passphrase instead.
  [self _call:@"generateKeyPair" params:params];
}

- (void)PGPKeyForPublicKeyBundle:(NSString *)keyBundle success:(void (^)(KBPGPKey *key))success failure:(KBCyptoErrorBlock)failure {
  GHWeakSelf blockSelf = self;
  [self _call:@"info" params:@{@"armored": keyBundle, @"success": ^(NSDictionary *dict) {
    NSError *error = nil;
    
    NSMutableDictionary *mdict = [dict mutableCopy];
    mdict[@"public_key_bundle"] = keyBundle;
    KBPGPKey *key = [MTLJSONAdapter modelOfClass:KBPGPKey.class fromJSONDictionary:mdict error:&error];
    if (!key) {
      [blockSelf _callback:^{ failure(error); }];
      return;
    }
    
    [blockSelf _callback:^{ success(key); }];
    
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
  }}];
}

- (void)_PGPKeyForExport:(NSDictionary *)info publicKeyArmored:(NSString *)publicKeyArmored publicKeyHex:(NSString *)publicKeyHex privateKeyArmoredNoPassword:(NSString *)privateKeyArmoredNoPassword privateKeyHexNoPassword:(NSString *)privateKeyHexNoPassword password:(NSString *)password success:(void (^)(KBPGPKey *PGPKey))success failure:(KBCyptoErrorBlock)failure {
  
  NSMutableDictionary *mdict = [info mutableCopy];
  mdict[@"public_key_bundle"] = publicKeyArmored;
  
  GHWeakSelf blockSelf = self;
  NSError *error = nil;
  KBPGPKey *key = [MTLJSONAdapter modelOfClass:KBPGPKey.class fromJSONDictionary:mdict error:&error];
  if (!key) {
    [blockSelf _callback:^{ failure(error); }];
    return;
  }
  
  if (privateKeyHexNoPassword && password) {
    GHDebug(@"Encrypting secret key");
    P3SKB *secretKey = [P3SKB P3SKBWithPrivateKey:[privateKeyHexNoPassword na_dataFromHexString] password:password publicKey:[publicKeyHex na_dataFromHexString] error:nil];
    if (!secretKey) {
      [blockSelf _callback:^{ failure(KBCryptoError(@"Couldn't dearmor")); }];
      return;
    }
    
    GHDebug(@"Encrypting armored key");
    TSTripleSec *tripleSec = [[TSTripleSec alloc] init];
    NSData *secretKeyArmoredEncrypted = [tripleSec encrypt:[privateKeyArmoredNoPassword dataUsingEncoding:NSUTF8StringEncoding] key:[password dataUsingEncoding:NSUTF8StringEncoding] error:nil];
    key.secretKeyArmoredEncrypted = secretKeyArmoredEncrypted;
    
    key.secretKey = secretKey;
    GHDebug(@"Done");
    [blockSelf _callback:^{ success(key); }];
  } else {
    [blockSelf _callback:^{ success(key); }];
  }
}

- (void)PGPKeyForPrivateKeyBundle:(NSString *)privateKeyBundle keyBundlePassword:(NSString *)keyBundlePassword password:(NSString *)password success:(void (^)(KBPGPKey *PGPKey))success failure:(KBCyptoErrorBlock)failure {
  GHWeakSelf blockSelf = self;
  
  GHDebug(@"Info");
  [self _call:@"info" params:@{@"armored": privateKeyBundle, @"passphrase": KBCOrNull(keyBundlePassword), @"success": ^(NSDictionary *dict) {
    GHDebug(@"Export");
    [blockSelf _call:@"exportAll" params:@{@"armored": privateKeyBundle, @"passphrase": KBCOrNull(keyBundlePassword), @"success": ^(NSString *publicKeyArmored, NSString *publicKeyHex, NSString *privateKeyArmoredNoPassword, NSString *privateKeyHexNoPassword) {
    
      [self _PGPKeyForExport:dict publicKeyArmored:publicKeyArmored publicKeyHex:publicKeyHex privateKeyArmoredNoPassword:privateKeyArmoredNoPassword privateKeyHexNoPassword:privateKeyHexNoPassword password:password success:success failure:failure];
      
    }, @"failure": ^(NSString *error) {
      [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
    }}];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
  }}];
}

- (void)PGPKeyForSecretKey:(P3SKB *)secretKey password:(NSString *)password success:(void (^)(KBPGPKey *PGPKey))success failure:(KBCyptoErrorBlock)failure {
  GHWeakSelf blockSelf = self;
  [self armoredKeyBundleFromSecretKey:secretKey password:password keyBundlePassword:nil success:^(NSString *armoredBundle) {
    GHDebug(@"Info");
    [blockSelf _call:@"info" params:@{@"armored": armoredBundle, @"success": ^(NSDictionary *dict) {
      
      [blockSelf _call:@"armorPublicKey" params:@{@"data": [secretKey.publicKey na_hexString], @"success": ^(NSString *publicKeyArmored) {
        
        NSMutableDictionary *mdict = [dict mutableCopy];
        mdict[@"public_key_bundle"] = publicKeyArmored;
        
        NSError *error = nil;
        KBPGPKey *key = [MTLJSONAdapter modelOfClass:KBPGPKey.class fromJSONDictionary:mdict error:&error];
        if (!key) {
          [blockSelf _callback:^{ failure(error); }];
          return;
        }
        
        key.secretKey = secretKey;
        
        NSAssert(password, @"No password");
        GHDebug(@"Encrypting armored key");
        TSTripleSec *tripleSec = [[TSTripleSec alloc] init];
        NSData *secretKeyArmoredEncrypted = [tripleSec encrypt:[armoredBundle dataUsingEncoding:NSUTF8StringEncoding] key:[password dataUsingEncoding:NSUTF8StringEncoding] error:nil];
        key.secretKeyArmoredEncrypted = secretKeyArmoredEncrypted;
        
        GHDebug(@"Done");
        [blockSelf _callback:^{ success(key); }];
        
      }, @"failure": ^(NSString *error) {
        [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
      }}];
    }, @"failure": ^(NSString *error) {
      [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
    }}];
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
  [self _call:@"checkPassword" params:@{@"armored": armoredKeyBundle, @"passphrase": KBCOrNull(password), @"success": ^() {
    [blockSelf _callback:^{ success(); }];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
  }}];
}

- (void)addArmoredKeyBundle:(NSString *)armoredKeyBundle success:(dispatch_block_t)success failure:(KBCyptoErrorBlock)failure {
  GHWeakSelf blockSelf = self;
  [self _call:@"addArmoredKeyBundle" params:@{@"armored": armoredKeyBundle, @"success": ^() {
    if (success) [blockSelf _callback:^{ success(); }];
  }, @"failure": ^(NSString *error) {
    if (failure) [blockSelf _callback:^{ failure(KBCryptoError(error)); }];
  }}];
}

NSError *KBCryptoError(NSString *message) {
  NSInteger errorCode = KBCryptoErrorCodeDefault;
  if ([message isEqualToString:@"Aborted"]) errorCode = KBCryptoErrorCodeCancelled;
  return [NSError errorWithDomain:@"KBCrypto" code:errorCode userInfo:@{NSLocalizedDescriptionKey:message}];
}

#pragma mark - 

// Hack to reload if the context is fucked up :(
- (void)resetIfNotReady:(dispatch_block_t)completion {
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC), _queue, ^{
    [self isReady:^(BOOL ready) {
      if (!ready) {
        GHDebug(@"Not ready, resetting");
        [self clearContext];
        [self generateContext];
        [self resetIfNotReady:completion];
      } else {
        completion();
      }
    }];
  });
}

@end
