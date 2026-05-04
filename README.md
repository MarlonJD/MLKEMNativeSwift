# MLKEMNativeSwift

Swift Package Manager wrapper for ML-KEM-768 on Apple platforms.

`MLKEMNativeSwift` wraps the portable C backend from
[`mlkem-native`](https://github.com/pq-code-package/mlkem-native) and exposes a
small Swift API shaped similarly to CryptoKit's ML-KEM API.

## Status

- Package version target: `0.1.0`
- Upstream C core: `Vendor/mlkem-native` git submodule
- Pinned upstream release: `v1.1.0`
- Pinned upstream commit: `d2cae2be522a67bfae26100fdb520576f1b2ef90`
- Backend: portable C only. Native assembly backends are not compiled in this
  package yet.
- Platform targets: iOS 13.0+, macOS 10.15+

This package does not claim FIPS validation. It uses an implementation of the
FIPS 203 ML-KEM algorithm from `mlkem-native`.

## Installation

Add the package to `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/MarlonJD/MLKEMNativeSwift.git", from: "0.1.0")
]
```

Then add `MLKEMNativeSwift` to your target dependencies:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "MLKEMNativeSwift", package: "MLKEMNativeSwift")
    ]
)
```

## Checkout

For development, clone with submodules:

```bash
git clone --recurse-submodules https://github.com/MarlonJD/MLKEMNativeSwift.git
cd MLKEMNativeSwift
```

For an existing checkout:

```bash
git submodule update --init --recursive
```

SwiftPM resolves submodules for dependency checkouts, but a top-level
development checkout still needs the normal Git submodule initialization step.

## Usage

```swift
import CryptoKit
import Foundation
import MLKEMNativeSwift

let privateKey = try MLKEMNative768.PrivateKey.generate()
let publicKeyBytes = privateKey.publicKey.rawRepresentation

let publicKey = try MLKEMNative768.PublicKey(rawRepresentation: publicKeyBytes)
let encapsulated = try publicKey.encapsulate()

let sharedSecret = try privateKey.decapsulate(encapsulated.ciphertext)
let sameSecret = encapsulated.sharedSecret
```

`sharedSecret` and `sameSecret` are `CryptoKit.SymmetricKey` values.

## Key Sizes

ML-KEM-768 sizes:

- Public key: 1184 bytes
- Ciphertext: 1088 bytes
- Shared secret: 32 bytes
- In-memory secret key: 2400 bytes

## Private Key Representation

The package stores private keys in an app-owned deterministic representation:

```text
KMLK1 || seed64 || publicKey1184
```

On load, the 2400-byte ML-KEM secret key is regenerated in memory with
`keypair_derand(seed64)`, and the stored public key is verified against the
regenerated public key.

This representation is intentionally compact and stable for app storage, but it
is still private key material. Store it in Keychain, an encrypted backup blob,
or another storage layer appropriate for your threat model.

## API

```swift
try MLKEMNative768.PrivateKey.generate()
try MLKEMNative768.PrivateKey(representation: data)
privateKey.representation
privateKey.publicKey.rawRepresentation

try MLKEMNative768.PublicKey(rawRepresentation: data)
try publicKey.encapsulate()
try privateKey.decapsulate(ciphertext)
```

## Development

Run tests:

```bash
swift test
```

The test suite includes generate/load roundtrips, invalid input coverage, and a
deterministic ML-KEM-768 vector using fixed keygen and encapsulation seeds.

## License

`MLKEMNativeSwift` wrapper code is released under the MIT license. See
[`LICENSE`](LICENSE).

The vendored upstream `mlkem-native` submodule is licensed separately under the
terms documented in `Vendor/mlkem-native/LICENSE`; at the pinned release, its
core source is available under Apache-2.0 OR ISC OR MIT. See
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
