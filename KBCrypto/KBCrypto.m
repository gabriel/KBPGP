//
//  KBCrypto.m
//  Keybase
//
//  Created by Gabriel on 7/1/14.
//  Copyright (c) 2014 Gabriel Handford. All rights reserved.
//

#import "KBCrypto.h"
#import "KBJSCore.h"
#import "KBSigner.h"

#import <GHKit/GHKit.h>
#import <ObjectiveSugar/ObjectiveSugar.h>
#import <NAChloride/NAChloride.h>

@interface KBCrypto ()
@property dispatch_queue_t queue;
@property dispatch_group_t group;
@property dispatch_semaphore_t callSem;
@property JSContext *context;
@property KBJSCore *JSCore;
@property id<KBKeyRing> keyRing;
@end

@implementation KBCrypto

- (instancetype)init {
  if ((self = [super init])) {
    _queue = dispatch_queue_create("KBCrypto", NULL);
    _group = dispatch_group_create();
    [self generateContext];
  }
  return self;
}

- (instancetype)initWithKeyRing:(id<KBKeyRing>)keyRing {
  if ((self = [self init])) {
    _keyRing = keyRing;
  }
  return self;
}

- (void)generateContext {
  JSContext *context = [[JSContext alloc] initWithVirtualMachine:[[JSVirtualMachine alloc] init]];
  context.exceptionHandler = ^(JSContext *context, JSValue *exception) {
    id obj = [exception toObject];
    GHDebug(@"Exception: %@, %@", [exception description], obj);
    [NSException raise:NSGenericException format:@"JS Exception"];
  };
  
  KBJSCore *JSCore = [[KBJSCore alloc] initWithContext:context];
  
  [JSCore load:@"keybase.js"];
  [JSCore load:@"keybase-kbpgp-jscore.js"];

  GHWeakSelf blockSelf = self;
  context[@"jscore"][@"kbcrypto"] = @{};
  
  //
  // Key fetch API
  // Called from kbpgp.js to fetch keys
  //
  context[@"jscore"][@"kbcrypto"][@"keyfetch"] = ^(NSArray *keyIds, KBKeyCapabilities capabilites, JSValue *success, JSValue *failure) {
    NSAssert(blockSelf.keyRing, @"No key rings");
    [_keyRing lookupKeyIds:keyIds capabilities:capabilites success:^(NSArray *keys) {
      if ([keys count] == 0) {
        [failure callWithArguments:@[NSStringWithFormat(@"No keys found for %@", keyIds)]];
        return;
      }
      
      id<KBKey> key = keys[0];
      
      if ([key isPasswordProtected]) {
        NSAssert(_passwordBlock, @"No password prompt");
        
        _passwordBlock(key, ^(NSString *password) {
          [success callWithArguments:@[key.bundle, KBCOrNull(key.userName), password]];
        });
      } else {
        [success callWithArguments:@[key.bundle, KBCOrNull(key.userName), NSNull.null]];
      }
    } failure:^(NSError *error) {
      [failure callWithArguments:@[[error localizedDescription]]];
    }];
  };
  
  _JSCore = JSCore;
  _context = context;
}

- (void)_callAsyncWait:(NSString *)method params:(NSDictionary *)params {
  GHWeakSelf blockSelf = self;
  dispatch_group_async(_group, _queue, ^{
    blockSelf.context[@"params"] = params;
    [blockSelf.context evaluateScript:method];

    // Only used to make the calls synchronous
    if (_callSem) dispatch_semaphore_wait(_callSem, DISPATCH_TIME_FOREVER);
  });
}

- (void)_callback:(dispatch_block_t)callback {
  dispatch_queue_t completionQueue = _completionQueue;
  if (!completionQueue) completionQueue = dispatch_get_main_queue();

  _context[@"params"] = nil;
  if (_callSem) dispatch_semaphore_signal(_callSem);
  dispatch_async(completionQueue, callback);
}

- (void)encryptText:(NSString *)text keyIds:(NSArray *)keyIds success:(void (^)(NSString *messageArmored))success failure:(void (^)(NSError *error))failure {
  
  NSAssert([keyIds count] == 1, @"Only support single encrypt");
  
  GHWeakSelf blockSelf = self;
  [_keyRing lookupKeyIds:keyIds capabilities:KBKeyCapabilitiesEncrypt success:^(NSArray *keys) {
    [blockSelf encryptText:text keyBundle:[keys[0] bundle] success:success failure:failure];
  } failure:failure];
}

- (void)encryptText:(NSString *)text keyBundle:(NSString *)keyBundle success:(void (^)(NSString *messageArmored))success failure:(void (^)(NSError *error))failure {
  GHWeakSelf blockSelf = self;
  [self _callAsyncWait:@"jscore.encrypt(params)" params:@{@"encrypt_for": keyBundle, @"text": text, @"success": ^(NSString *messageArmored) {
    [blockSelf _callback:^{ success(messageArmored); }];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(GHNSError(-1, error)); }];
  }}];
}

- (void)encryptAndSignText:(NSString *)text encryptForKeyIds:(NSArray *)encryptForKeyIds signForKeyIds:(NSArray *)signForKeyIds success:(void (^)(NSString *messageArmored))success failure:(void (^)(NSError *error))failure {
  
  NSAssert([encryptForKeyIds count] == 1, @"Only support single encrypt");
  NSAssert([signForKeyIds count] == 1, @"Only support single sign");
  
  GHWeakSelf blockSelf = self;
  [_keyRing lookupKeyIds:encryptForKeyIds capabilities:KBKeyCapabilitiesEncrypt success:^(NSArray *encryptKeys) {
    [_keyRing lookupKeyIds:signForKeyIds capabilities:KBKeyCapabilitiesSign success:^(NSArray *signKeys) {
      _passwordBlock(signKeys[0], ^(NSString *signKeyPassword) {
        [blockSelf encryptAndSignText:text encryptKeyBundle:[encryptKeys[0] bundle] signKeyBundle:[signKeys[0] bundle] password:signKeyPassword success:success failure:failure];
      });
    } failure:failure];
  } failure:failure];
}

- (void)encryptAndSignText:(NSString *)text encryptKeyBundle:(NSString *)encryptKeyBundle signKeyBundle:(NSString *)signKeyBundle password:(NSString *)password success:(void (^)(NSString *messageArmored))success failure:(void (^)(NSError *error))failure {
  GHWeakSelf blockSelf = self;
  [self _callAsyncWait:@"jscore.encrypt(params)" params:@{@"encrypt_for": encryptKeyBundle, @"sign_with": signKeyBundle, @"passphrase": password, @"text": text, @"success": ^(NSString *messageArmored) {
    [blockSelf _callback:^{ success(messageArmored); }];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(GHNSError(-1, error)); }];
  }}];
}

- (void)signText:(NSString *)text keyIds:(NSArray *)keyIds success:(void (^)(NSString *clearTextArmored))success failure:(void (^)(NSError *error))failure {
  GHWeakSelf blockSelf = self;
  [_keyRing lookupKeyIds:keyIds capabilities:KBKeyCapabilitiesSign success:^(NSArray *keys) {
    _passwordBlock(keys[0], ^(NSString *password) {
      [blockSelf signText:text keyBundle:[keys[0] bundle] password:password success:success failure:failure];
    });
  } failure:failure];
}

- (void)signText:(NSString *)text keyBundle:(NSString *)keyBundle password:(NSString *)password success:(void (^)(NSString *clearTextArmored))success failure:(void (^)(NSError *error))failure {
  NSParameterAssert(keyBundle);
  
  GHWeakSelf blockSelf = self;
  [self _callAsyncWait:@"jscore.sign(params)" params:@{@"private_key_armored": keyBundle, @"passphrase": password, @"text": text, @"success": ^(NSString *clearTextArmored) {
    [blockSelf _callback:^{ success(clearTextArmored); }];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(GHNSError(-1, error)); }];
  }}];
}

- (void)_verifySigners:(NSArray *)signerDicts plainText:(NSString *)plainText success:(void (^)(NSString *plainText, NSArray *verifiedSigners))success failure:(void (^)(NSError *error))failure {
  NSArray *signers = [signerDicts map:^id(id signerDict) { return [[KBSigner alloc] initWithKeyId:signerDict[@"key_id"] userName:signerDict[@"username"]]; }];
  GHWeakSelf blockSelf = self;
  [_keyRing verifySigners:signers success:^(NSArray *verified, NSArray *failed) {
//    if ([failed count] > 0) {
//      NSString *errorMessage = NSStringWithFormat(@"Decryption failed to verify the signature: %@, %@", [failed[0] keyId], [failed[0] userName]);
//      [blockSelf _callback:^{ failure(GHNSError(-1, errorMessage)); }];
//      return;
//    }
    
    [blockSelf _callback:^{ success(plainText, verified); }];
  } failure:^(NSError *error) {
    [blockSelf _callback:^{ failure(GHNSError(-1, error)); }];
  }];
}

- (void)decryptMessageArmored:(NSString *)messageArmored success:(void (^)(NSString *plainText, NSArray *signers))success failure:(void (^)(NSError *error))failure {
  GHWeakSelf blockSelf = self;
  [self _callAsyncWait:@"jscore.decrypt(params)" params:@{@"message_armored": messageArmored, @"success": ^(NSString *plainText, NSArray *signerDicts) {
    [blockSelf _verifySigners:signerDicts plainText:plainText success:success failure:failure];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(GHNSError(-1, error)); }];
  }}];
}

- (void)verifyMessageArmored:(NSString *)messageArmored success:(void (^)(NSString *plainText, NSArray *verifiedSigners))success failure:(void (^)(NSError *failure))failure {
  GHWeakSelf blockSelf = self;
  [self _callAsyncWait:@"jscore.verify(params)" params:@{@"message_armored": messageArmored, @"success": ^(NSString *plainText, NSArray *signerDicts) {
    [blockSelf _verifySigners:signerDicts plainText:plainText success:success failure:failure];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(GHNSError(-1, error)); }];
  }}];
}

- (void)armor:(NSData *)data messageType:(KBMessageType)messageType success:(void (^)(NSString *encoded))success failure:(void (^)(NSError *failure))failure {
  NSString *methodName;
  switch (messageType) {
    case KBMessageTypePrivateKey: {
      methodName = @"jscore.armorPrivateKey(params)";
      break;
    }
    case KBMessageTypePublicKey: {
      methodName = @"jscore.armorPublicKey(params)";
      break;
    }
  }
  
  GHWeakSelf blockSelf = self;
  [self _callAsyncWait:methodName params:@{@"data": [data na_hexString], @"success": ^(NSString *encoded) {
    [blockSelf _callback:^{ success(encoded); }];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(GHNSError(-1, error)); }];
  }}];
}

- (void)dearmor:(NSString *)armored success:(void (^)(NSData *data))success failure:(void (^)(NSError *failure))failure {
  GHWeakSelf blockSelf = self;
  [self _callAsyncWait:@"jscore.dearmor(params)" params:@{@"armored": armored, @"success": ^(NSString *hex) {
    NSData *data = [hex na_dataFromHexString];
    [blockSelf _callback:^{ success(data); }];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(GHNSError(-1, error)); }];
  }}];
}

- (void)generateKeyWithNumBits:(NSUInteger)numBits numBitsSubKeys:(NSUInteger)numBitsSubKeys userName:(NSString *)userName userEmail:(NSString *)userEmail password:(NSString *)password success:(void (^)(NSString *privateKeyArmored, NSString *publicKeyArmored, NSString *keyId))success failure:(void (^)(NSError *error))failure {
  
  GHWeakSelf blockSelf = self;
  NSString *userId = NSStringWithFormat(@"%@ <%@>", userName, userEmail);
  [self _callAsyncWait:@"jscore.generateKeyPair(params)" params:@{@"nbits": @(numBits), @"nbits_subkeys": @(numBitsSubKeys), @"userid": userId, @"passphrase": password, @"success": ^(NSString *publicKeyArmored, NSString *privateKeyArmored, NSString *keyId) {
    [blockSelf _callback:^{ success(publicKeyArmored, privateKeyArmored, keyId); }];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(GHNSError(-1, error)); }];
  }}];
}

#pragma mark -

- (void)prepare {
  NSAssert(!_callSem, @"Prepare already called");
  _callSem = dispatch_semaphore_create(0);
}

- (BOOL)wait:(NSTimeInterval)timeout {
  NSAssert(_callSem, @"Call prepare before wait");
  BOOL waited = dispatch_group_wait(_group, dispatch_time(DISPATCH_TIME_NOW, timeout * NSEC_PER_SEC)) == 0;
  if (_callSem) self.callSem = nil;
  return waited;
}

@end
