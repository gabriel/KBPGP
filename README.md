KBCrypto
===========

PGP for iOS/OSX, using [kbpgp](https://github.com/keybase/kbpgp).

# Install

[CocoaPods](http://cocoapods.org) is a dependency manager for Objective-C, which automates and simplifies the process of using 3rd-party libraries in your projects.

## Podfile

```ruby
platform :ios, "7.0"
pod "KBCrypto"
```

# Encrypt

```objc
KBCrypto *crypto = [[KBCrypto alloc] init];
[crypto encryptText:@"This is a secret message" keyBundle:@"-----BEGIN PGP PUBLIC KEY..." success:^(NSString *messageArmored) {
  NSLog(@"%@", messageArmored);
} failure:^(NSError *error) {
  NSLog(@"Error: %@", [error localizedDescription]);
}];
```

# Encrypt & Sign

```objc
KBCrypto *crypto = [[KBCrypto alloc] init];
[crypto encryptText:@"This is a secret signed message" keyBundle:@"-----BEGIN PGP PUBLIC KEY..." keyBundleForSign:@"-----BEGIN PGP PRIVATE KEY..." passwordForSign:@"toomanysecrets" success:^(NSString *messageArmored) {
  NSLog(@"%@", messageArmored);
} failure:^(NSError *error) {
  NSLog(@"Error: %@", [error localizedDescription]);
}];
```

# Decrypt

```objc
KBCrypto *crypto = [[KBCrypto alloc] init];
[crypto decryptMessageArmored:messageArmored keyBundle:@"-----BEGIN PGP PRIVATE KEY..." password:@"toomanysecrets" success:^(NSString *plainText, NSArray *verifiedSigners) {
  NSLog(@"Decrypted: %@", plainText);
} failure:^(NSError *error) {
  NSLog(@"Error: %@", [error localizedDescription]);
}];

```

# Sign

```objc
KBCrypto *crypto = [[KBCrypto alloc] init];
[crypto signText:@"This is a secret message" keyBundle:@"-----BEGIN PGP PRIVATE KEY..." password:@"toomanysecrets" success:^(NSString *clearTextArmored) {
  NSLog(@"%@", clearTextArmored);
} failure:^(NSError *error) {
  NSLog(@"Error: %@", [error localizedDescription]);
}];
```

# Verify

```objc
KBKeyRing *keyRing = ...;
KBCrypto *crypto = [[KBCrypto alloc] initWithKeyRing:keyRing];

[crypto verifyMessageArmored:clearTextArmored success:^(NSString *plainText, NSArray *verifiedSigners) {
  NSLog(@"Verified: %@", plainText);
} failure:^(NSError *error) {
  NSLog(@"Error: %@", [error localizedDescription]);
}];
```

# Key Bundles

For public keys, only an armored PGP string is accepted.

For private keyBundle, you can specify either a armored PGP string, or [P3SKB](https://github.com/gabriel/TSTripleSec#p3skb) data base64 encoded string.

```objc
P3SKB *secretKey = ...;
NSString *keyBundleAsP3SKB = [[secretKey data] base64EncodedStringWithOptions:0];
```

# Key Ring

```objc
KBKeyRing *keyRing = [[KBKeyRing alloc] init];

KBKeyBundle *publicKey1 = [[KBKeyBundle alloc] initWithBundle:[self loadFile:@"user1_public.asc"] userId:@"gabrielhlocal2" fingerprint:@"AFB10F6A5895F5B1D67851861296617A289D5C6B" secret:NO];
[keyRing addKey:publicKey1 keyIds:@[@"89ae977e1bc670e5"] capabilities:KBKeyCapabilitiesEncrypt|KBKeyCapabilitiesVerify];

return keyRing;
```

# Generate Keys

Generates RSA key pair with appropriate defaults (4096 key with subkeys).

```objc
KBCrypto *crypto = [[KBCrypto alloc] init];
[crypto generateKeyWithUserName:@"keybase.io/crypto" userEmail:@"user@email.com" keyAlgorithm:KBKeyAlgorithmRSA password:@"toomanysecrets" progress:^(KBKeyGenProgress *progress) {
  NSLog(@"Progress: %@", [progress progressDescription]);
  // Return NO to cancel, which will throw an "Aborted" error
  return YES;
} success:^(P3SKB *privateKey, NSString *publicKeyArmored, NSString *keyFingerprint) {
  // Generated private key (P3SKB format, encrypted using TripleSec)

} failure:^(NSError *error) {
  NSLog(@"Error: %@", [error localizedDescription]);
}];
```

# Armor/Dearmor

```objc
NSData *data = ...;
[crypto armorPublicKey:data success:^(NSString *publicKeyArmored) {
  
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

