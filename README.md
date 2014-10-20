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
[crypto encryptText:@"This is a secret message" keyBundles:@[@"-----BEGIN PGP PUBLIC KEY..."] success:^(NSString *messageArmored) {
  NSLog(@"%@", messageArmored);
} failure:^(NSError *error) {
  NSLog(@"Error: %@", [error localizedDescription]);
}];
```

# Encrypt & Sign

```objc
KBCrypto *crypto = [[KBCrypto alloc] init];
[crypto encryptText:@"This is a secret signed message" keyBundles:@[@"-----BEGIN PGP PUBLIC KEY..."] keyBundleForSign:@"-----BEGIN PGP PRIVATE KEY..." passwordForSign:@"toomanysecrets" success:^(NSString *messageArmored) {
  NSLog(@"%@", messageArmored);
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

# Unbox (Decrypt & Verify)

```objc
KBCrypto *crypto = [[KBCrypto alloc] init];
[crypto setKeyRing:... passwordBlock:...];

[crypto unboxMessageArmored:messageArmored success:^(KBPGPMessage *message) {
  NSLog(@"Decrypted: %@", [message text]);
} failure:^(NSError *error) {
  NSLog(@"Error: %@", [error localizedDescription]);
}];
```

# Key Bundles

A key bundle is a string which can represent:

* An armored PGP public key
* An armored PGP private key
* [P3SKB](https://github.com/gabriel/TSTripleSec#p3skb) data (Base64 encoded)

```objc
NSString *armoredPublicKeyBundle = @"-----BEGIN PGP PUBLIC KEY...";
NSString *armoredPrivateKeyBundle = @"-----BEGIN PGP PRIVATE KEY...";

P3SKB *secretKey = ...;
NSString *secretKeyBundle = [[secretKey data] base64EncodedStringWithOptions:0];
```

# Key (KBKey)

A key is the simplest representation of a key:

* An armored public key bundle.
* A fingerprint (string), which is the unique identifier for the key.
* A P3SKB secret key (or nil if public only)

# PGP Key (KBPGPKey)

A PGP key is a more detailed version of a key, which stores extra info such as the algorithm, size, subkeys, user ids, etc. 

You can get a PGP key from a bundle:

```objc
KBCrypto *crypto = [[KBCrypto alloc] init];
[crypto PGPKeyForPublicKeyBundle:@"-----BEGIN PGP PUBLIC KEY..." success:^(KBPGPKey *PGPKey) { 
  // PGP key
} failure:^(NSError *error) {
  NSLog(@"Error: %@", [error localizedDescription]);
}
```

# Key Ring (KBKeyRing, KBPGPKeyRing)

A key ring stores keys.

```objc
KBPGPKeyRing *keyRing = [[KBPGPKeyRing alloc] init];

KBPGPKey key = ...
[keyRing addPGPKey:key];

return keyRing;
```

# Generate Keys

Generates RSA key pair with appropriate defaults (4096 key with subkeys).

```objc
KBCrypto *crypto = [[KBCrypto alloc] init];
[crypto generateKeyWithUserIds:... keyAlgorithm:KBKeyAlgorithmRSA password:@"toomanysecrets" progress:^(KBKeyGenProgress *progress) {
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
[crypto armoredKeyBundleFromPublicKey:data success:^(NSString *publicKeyArmored) {
  
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

