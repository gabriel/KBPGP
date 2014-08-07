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

@interface KBCrypto ()
@property dispatch_queue_t queue;
@property JSContext *context;
@property KBJSCore *JSCore;
@property id<KBKeyRing> keyRing;
@end

@implementation KBCrypto

- (instancetype)init {
  if ((self = [super init])) {
    _queue = dispatch_queue_create("KBCrypto", NULL);
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
  // Called from javascript to fetch keys
  //
  context[@"jscore"][@"kbcrypto"][@"keyfetch"] = ^(NSArray *keyIds, KBKeyCapabilities capabilites, JSValue *success, JSValue *failure) {
    NSAssert(blockSelf.keyRing, @"No key rings");
    [blockSelf.keyRing lookupKeyIds:keyIds capabilities:capabilites success:^(NSArray *keys) {
      if ([keys count] == 0) {
        [failure callWithArguments:@[NSStringWithFormat(@"No keys found for %@", keyIds)]];
        return;
      }
      
      id<KBKey> key = keys[0];
      
      // Key fetch should return secret keys
      if ([key isSecret]) {
        [failure callWithArguments:@[NSStringWithFormat(@"Key fetch returned a secret key")]];
        return;
      }
      
//      if ([key isSecret]) {
//        NSAssert(_passwordBlock, @"No password prompt");
//        _passwordBlock(key, ^(NSString *password) {
//          [success callWithArguments:@[key.bundle, password]];
//        });
//      } else {
      [success callWithArguments:@[key.bundle]];
      
    } failure:^(NSError *error) {
      [failure callWithArguments:@[[error localizedDescription]]];
    }];
  };
  
  _JSCore = JSCore;
  _context = context;
}

- (void)_call:(NSString *)method params:(NSDictionary *)params {
  GHWeakSelf blockSelf = self;
  dispatch_async(_queue, ^{
    blockSelf.context[@"params"] = params;
    [blockSelf.context evaluateScript:NSStringWithFormat(@"%@(params)", method)];
  });
}

- (void)_callback:(dispatch_block_t)callback {
  //_context[@"params"] = nil;
  dispatch_async(dispatch_get_main_queue(), callback);
}

- (void)encryptText:(NSString *)text keyBundle:(NSString *)keyBundle success:(void (^)(NSString *messageArmored))success failure:(void (^)(NSError *error))failure {
  GHWeakSelf blockSelf = self;
  [self _call:@"jscore.encrypt" params:@{@"encrypt_for": keyBundle, @"text": text, @"success": ^(NSString *messageArmored) {
    [blockSelf _callback:^{ success(messageArmored); }];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(GHNSError(-1, error)); }];
  }}];
}

- (void)encryptText:(NSString *)text keyBundle:(NSString *)keyBundle keyBundleForSign:(NSString *)keyBundleForSign passwordForSign:(NSString *)passwordForSign success:(void (^)(NSString *messageArmored))success failure:(void (^)(NSError *error))failure {
  GHWeakSelf blockSelf = self;
  [self _call:@"jscore.encrypt" params:@{@"encrypt_for": keyBundle, @"sign_with": KBCOrNull(keyBundleForSign), @"passphrase": passwordForSign, @"text": text, @"success": ^(NSString *messageArmored) {
    [blockSelf _callback:^{ success(messageArmored); }];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(GHNSError(-1, error)); }];
  }}];
}

- (void)signText:(NSString *)text keyBundle:(NSString *)keyBundle password:(NSString *)password success:(void (^)(NSString *clearTextArmored))success failure:(void (^)(NSError *error))failure {
  NSParameterAssert(keyBundle);
  
  GHWeakSelf blockSelf = self;
  [self _call:@"jscore.sign" params:@{@"sign_with": keyBundle, @"passphrase": password, @"text": text, @"success": ^(NSString *clearTextArmored) {
    [blockSelf _callback:^{ success(clearTextArmored); }];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(GHNSError(-1, error)); }];
  }}];
}

- (void)_verifySigners:(NSArray *)signers plainText:(NSString *)plainText success:(void (^)(NSString *plainText, NSArray *verified))success failure:(void (^)(NSError *error))failure {
  GHWeakSelf blockSelf = self;
  
  if ([_keyRing respondsToSelector:@selector(verifyKeyFingerprints:success:failure:)]) {
    [_keyRing verifyKeyFingerprints:signers success:^(NSArray *verified, NSArray *failed) {
      [blockSelf _callback:^{ success(plainText, verified); }];
    } failure:^(NSError *error) {
      [blockSelf _callback:^{ failure(GHNSError(-1, error)); }];
    }];
  } else {
    [blockSelf _callback:^{ success(plainText, @[]); }];
  }
}

- (void)decryptMessageArmored:(NSString *)messageArmored keyBundle:(NSString *)keyBundle password:(NSString *)password success:(void (^)(NSString *plainText, NSArray *signedWithKeyFingerprints))success failure:(void (^)(NSError *error))failure {
  GHWeakSelf blockSelf = self;
  [self _call:@"jscore.decrypt" params:@{@"message_armored": messageArmored, @"decrypt_with": keyBundle, @"passphrase": password, @"success": ^(NSString *plainText, NSArray *signedWithKeyFingerprints) {
    [blockSelf _verifySigners:signedWithKeyFingerprints plainText:plainText success:success failure:failure];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(GHNSError(-1, error)); }];
  }}];
}

- (void)verifyMessageArmored:(NSString *)messageArmored success:(void (^)(NSString *plainText, NSArray *signedWithKeyFingerprints))success failure:(void (^)(NSError *failure))failure {
  GHWeakSelf blockSelf = self;
  [self _call:@"jscore.verify" params:@{@"message_armored": messageArmored, @"success": ^(NSString *plainText, NSArray *signedWithKeyFingerprints) {
    [blockSelf _verifySigners:signedWithKeyFingerprints plainText:plainText success:success failure:failure];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(GHNSError(-1, error)); }];
  }}];
}

- (void)armor:(NSData *)data messageType:(KBMessageType)messageType success:(void (^)(NSString *encoded))success failure:(void (^)(NSError *failure))failure {
  NSString *methodName;
  switch (messageType) {
    case KBMessageTypePrivateKey: {
      methodName = @"jscore.armorPrivateKey";
      break;
    }
    case KBMessageTypePublicKey: {
      methodName = @"jscore.armorPublicKey";
      break;
    }
  }
  
  GHWeakSelf blockSelf = self;
  [self _call:methodName params:@{@"data": [data na_hexString], @"success": ^(NSString *encoded) {
    [blockSelf _callback:^{ success(encoded); }];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(GHNSError(-1, error)); }];
  }}];
}

- (void)dearmor:(NSString *)armored success:(void (^)(NSData *data))success failure:(void (^)(NSError *failure))failure {
  GHWeakSelf blockSelf = self;
  [self _call:@"jscore.dearmor" params:@{@"armored": armored, @"success": ^(NSString *hex) {
    NSData *data = [hex na_dataFromHexString];
    [blockSelf _callback:^{ success(data); }];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(GHNSError(-1, error)); }];
  }}];
}

- (void)generateKeyWithNumBits:(NSUInteger)numBits numBitsSubKeys:(NSUInteger)numBitsSubKeys userName:(NSString *)userName userEmail:(NSString *)userEmail password:(NSString *)password success:(void (^)(NSString *privateKeyArmored, NSString *publicKeyArmored, NSString *keyId))success failure:(void (^)(NSError *error))failure {
  
  GHWeakSelf blockSelf = self;
  NSString *userId = NSStringWithFormat(@"%@ <%@>", userName, userEmail);
  [self _call:@"jscore.generateKeyPair" params:@{@"nbits": @(numBits), @"nbits_subkeys": @(numBitsSubKeys), @"userid": userId, @"passphrase": password, @"success": ^(NSString *publicKeyArmored, NSString *privateKeyArmored, NSString *keyId) {
    [blockSelf _callback:^{ success(publicKeyArmored, privateKeyArmored, keyId); }];
  }, @"failure": ^(NSString *error) {
    [blockSelf _callback:^{ failure(GHNSError(-1, error)); }];
  }}];
}

@end
