KBCrypto
===========

PGP for iOS/OSX, using [kbgpg](https://github.com/keybase/kbpgp).

# Install

[CocoaPods](http://cocoapods.org) is a dependency manager for Objective-C, which automates and simplifies the process of using 3rd-party libraries in your projects.

## Podfile

```ruby
platform :ios, "7.0"
pod "KBCrypto"
```

# Encrypt

```objc
KBKeyRing *keyRing = ...;
KBCrypto *crypto = [[KBCrypto alloc] initWithKeyRing:keyRing];

[crypto encryptText:@"This is a secret message" keyIds:@[@"89ae977e1bc670e5"] success:^(NSString *messageArmored) {
  NSLog(@"%@", messageArmored);
} failure:^(NSError *error) {
  NSLog(@"Error: %@", [error localizedDescription]);
}];
```

# Encrypt & Sign

```objc
KBKeyRing *keyRing = ...;
KBCrypto *crypto = [[KBCrypto alloc] initWithKeyRing:keyRing];

[crypto encryptAndSignText:@"This is a secret signed message" encryptForKeyIds:@[@"89ae977e1bc670e5"] signForKeyIds:@[@"89ae977e1bc670e5"] success:^(NSString *messageArmored) {
  NSLog(@"%@", messageArmored);
} failure:^(NSError *error) {
  NSLog(@"Error: %@", [error localizedDescription]);
}];
```

# Decrypt & Verify

```objc
KBKeyRing *keyRing = ...;
KBCrypto *crypto = [[KBCrypto alloc] initWithKeyRing:keyRing];

crypto.passwordBlock = ^(id<KBKey> key, KBCryptoPasswordCompletionBlock completionBlock) { 
  NSString *password = ...;
  completionBlock(password); 
};

[crypto decryptMessageArmored:messageArmored success:^(NSString *plainText, NSArray *verifiedSigners) {
  NSLog(@"Decrypted: %@", plainText);
} failure:^(NSError *error) {
  NSLog(@"Error: %@", [error localizedDescription]);
}];

```

# Sign

```objc
KBKeyRing *keyRing = ...;
KBCrypto *crypto = [[KBCrypto alloc] initWithKeyRing:keyRing];

crypto.passwordBlock = ^(id<KBKey> key, KBCryptoPasswordCompletionBlock completionBlock) { 
  NSString *password = ...;
  completionBlock(password); 
};

[crypto signText:@"This is a secret message" keyIds:@[@"89ae977e1bc670e5"] success:^(NSString *clearTextArmored) {
  NSLog(@"%@", clearTextArmored);
} failure:^(NSError *error) {
  NSLog(@"Error: %@", [error localizedDescription]);
}];
```

# Verify

```
KBKeyRing *keyRing = ...;
KBCrypto *crypto = [[KBCrypto alloc] initWithKeyRing:keyRing];

[crypto verifyMessageArmored:clearTextArmored success:^(NSString *plainText, NSArray *verifiedSigners) {
  NSLog(@"Verified: %@", plainText);
} failure:^(NSError *error) {
  NSLog(@"Error: %@", [error localizedDescription]);
}];
```

# Key Ring

```objc
KBKeyRing *keyRing = [[KBKeyRing alloc] init];

[keyRing addKey:[[KBKey alloc] initWithKeyId:@"89ae977e1bc670e5" bundle:[self loadFile:@"kbuser_public.asc"]  userName:@"kbuser" capabilities:KBKeyCapabilitiesEncrypt|KBKeyCapabilitiesVerify passwordProtected:NO]];
[keyRing addKey:[[KBKey alloc] initWithKeyId:@"d53374f55303d0ea" bundle:[self loadFile:@"kbuser_private.asc"]  userName:@"kbuser" capabilities:KBKeyCapabilitiesDecrypt passwordProtected:YES]];
[keyRing addKey:[[KBKey alloc] initWithKeyId:@"89ae977e1bc670e5" bundle:[self loadFile:@"kbuser_private.asc"]  userName:@"kbuser" capabilities:KBKeyCapabilitiesSign passwordProtected:YES]];

[keyRing addKey:[[KBKey alloc] initWithKeyId:@"4bf812991a9c76ab" bundle:[self loadFile:@"gpguser_public.asc"]  userName:nil capabilities:KBKeyCapabilitiesEncrypt|KBKeyCapabilitiesVerify  passwordProtected:NO]];
[keyRing addKey:[[KBKey alloc] initWithKeyId:@"49d182780818ea2d" bundle:[self loadFile:@"gpguser_private.asc"]  userName:nil capabilities:KBKeyCapabilitiesDecrypt passwordProtected:YES]];
[keyRing addKey:[[KBKey alloc] initWithKeyId:@"4bf812991a9c76ab" bundle:[self loadFile:@"gpguser_private.asc"]  userName:nil capabilities:KBKeyCapabilitiesSign passwordProtected:YES]];

return keyRing;
```

# Generate Keys

```objc
KBCrypto *crypto = [[KBCrypto alloc] init];
[crypto generateKeyWithNumBits:4096 numBitsSubKeys:2048 userName:@"keybase.io/crypto" userEmail:@"user@email.com" password:@"toomanysecrets" success:^(NSString *privateKeyArmored, NSString *publicKeyArmored, NSString *keyId) {
  
} failure:^(NSError *error) {
  NSLog(@"Error: %@", [error localizedDescription]);
}];
```

# Armor/Dearmor

```objc
NSData *privateKeyData = ...;
[crypto armor:privateKeyData messageType:KBMessageTypePrivateKey success:^(NSString *privateKeyArmored) {
  // Private key as PGP armored text
} failure:^(NSError *error) {
  NSLog(@"Error: %@", [error localizedDescription]);
}];
```

```objc
NSString *keyArmored = @"-----BEGIN PGP ...";
[crypto dearmor:keyArmored success:^(NSData *keyData) {
  // Key as binary
} failure:^(NSError *error) {
  NSLog(@"Error: %@", [error localizedDescription]);
}];
```

