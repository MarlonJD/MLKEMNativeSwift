import CMLKEMNativeSwift
import CryptoKit
import Foundation
import Security

/// Errors thrown by the MLKEMNativeSwift wrapper.
public enum MLKEMError: Error, Equatable {
    case invalidPublicKey
    case invalidPrivateKeyRepresentation
    case invalidCiphertext
    case randomGenerationFailed
    case operationFailed
}

/// ML-KEM-768 operations and byte-size constants.
public enum MLKEMNative768 {
    /// Raw ML-KEM-768 public key length, in bytes.
    public static let publicKeyBytes = Int(MLKEM_NATIVE_SWIFT_768_PUBLIC_KEY_BYTES)
    /// Raw ML-KEM-768 ciphertext length, in bytes.
    public static let ciphertextBytes = Int(MLKEM_NATIVE_SWIFT_768_CIPHERTEXT_BYTES)
    /// ML-KEM shared secret length, in bytes.
    public static let sharedSecretBytes = Int(MLKEM_NATIVE_SWIFT_768_SHARED_SECRET_BYTES)
    /// Regenerated in-memory secret key length, in bytes.
    public static let secretKeyBytes = Int(MLKEM_NATIVE_SWIFT_768_SECRET_KEY_BYTES)
    /// Deterministic key generation seed length, in bytes.
    public static let keypairSeedBytes = Int(MLKEM_NATIVE_SWIFT_768_KEYPAIR_SEED_BYTES)
    /// Deterministic encapsulation seed length, in bytes.
    public static let encapsulationSeedBytes = Int(MLKEM_NATIVE_SWIFT_768_ENCAPSULATION_SEED_BYTES)

    /// An ML-KEM-768 private key.
    ///
    /// `representation` is a compact app-owned format:
    /// `KMLK1 || seed64 || publicKey1184`.
    public struct PrivateKey: Sendable {
        private static let magic = Data([0x4B, 0x4D, 0x4C, 0x4B, 0x31]) // KMLK1

        private let seed: Data
        private let secretKey: Data
        /// The public key corresponding to this private key.
        public let publicKey: PublicKey

        /// Generates a fresh ML-KEM-768 private key using `SecRandomCopyBytes`.
        public static func generate() throws -> PrivateKey {
            try PrivateKey(seed: randomBytes(count: keypairSeedBytes))
        }

        /// Loads a private key from `KMLK1 || seed64 || publicKey1184`.
        ///
        /// The in-memory ML-KEM secret key is regenerated from `seed64`, and the
        /// stored public key is verified against the regenerated public key.
        public init(representation: Data) throws {
            let expectedCount = Self.magic.count + keypairSeedBytes + publicKeyBytes
            guard representation.count == expectedCount,
                  representation.prefix(Self.magic.count) == Self.magic else {
                throw MLKEMError.invalidPrivateKeyRepresentation
            }

            let seedStart = Self.magic.count
            let seedEnd = seedStart + keypairSeedBytes
            let seed = Data(representation[seedStart..<seedEnd])
            let expectedPublicKey = Data(representation[seedEnd...])
            try self.init(seed: seed, expectedPublicKey: expectedPublicKey)
        }

        /// Loads a private key from a deterministic keygen seed and expected public key.
        ///
        /// This is useful for migrations from systems that separately expose the
        /// ML-KEM key generation seed and raw public key.
        public init(seedRepresentation: Data, publicKeyRepresentation: Data) throws {
            try self.init(seed: seedRepresentation, expectedPublicKey: publicKeyRepresentation)
        }

        var seedRepresentation: Data {
            seed
        }

        /// Compact private-key representation: `KMLK1 || seed64 || publicKey1184`.
        public var representation: Data {
            var data = Self.magic
            data.append(seed)
            data.append(publicKey.rawRepresentation)
            return data
        }

        init(seed: Data, expectedPublicKey: Data? = nil) throws {
            guard seed.count == keypairSeedBytes else {
                throw MLKEMError.invalidPrivateKeyRepresentation
            }

            var pk = [UInt8](repeating: 0, count: publicKeyBytes)
            var sk = [UInt8](repeating: 0, count: secretKeyBytes)
            let status = seed.withUnsafeBytes { seedBytes in
                pk.withUnsafeMutableBytes { pkBytes in
                    sk.withUnsafeMutableBytes { skBytes in
                        mlkem_native_swift_768_keypair_derand(
                            pkBytes.bindMemory(to: UInt8.self).baseAddress!,
                            skBytes.bindMemory(to: UInt8.self).baseAddress!,
                            seedBytes.bindMemory(to: UInt8.self).baseAddress!
                        )
                    }
                }
            }
            guard status == 0 else {
                throw MLKEMError.operationFailed
            }

            let publicKeyData = Data(pk)
            if let expectedPublicKey, expectedPublicKey != publicKeyData {
                throw MLKEMError.invalidPrivateKeyRepresentation
            }

            self.seed = seed
            self.secretKey = Data(sk)
            self.publicKey = try PublicKey(rawRepresentation: publicKeyData)
        }

        /// Decapsulates an ML-KEM-768 ciphertext and returns the shared secret.
        public func decapsulate(_ ciphertext: Data) throws -> SymmetricKey {
            guard ciphertext.count == ciphertextBytes else {
                throw MLKEMError.invalidCiphertext
            }

            var ss = [UInt8](repeating: 0, count: sharedSecretBytes)
            let status = ciphertext.withUnsafeBytes { ctBytes in
                secretKey.withUnsafeBytes { skBytes in
                    ss.withUnsafeMutableBytes { ssBytes in
                        mlkem_native_swift_768_decapsulate(
                            ssBytes.bindMemory(to: UInt8.self).baseAddress!,
                            ctBytes.bindMemory(to: UInt8.self).baseAddress!,
                            skBytes.bindMemory(to: UInt8.self).baseAddress!
                        )
                    }
                }
            }
            guard status == 0 else {
                throw MLKEMError.operationFailed
            }
            return SymmetricKey(data: Data(ss))
        }
    }

    /// An ML-KEM-768 public key.
    public struct PublicKey: Sendable {
        /// Raw 1184-byte public-key representation.
        public let rawRepresentation: Data

        /// Loads and validates a raw ML-KEM-768 public key.
        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == publicKeyBytes else {
                throw MLKEMError.invalidPublicKey
            }
            let status = rawRepresentation.withUnsafeBytes { pkBytes in
                mlkem_native_swift_768_check_public_key(
                    pkBytes.bindMemory(to: UInt8.self).baseAddress!
                )
            }
            guard status == 0 else {
                throw MLKEMError.invalidPublicKey
            }
            self.rawRepresentation = rawRepresentation
        }

        /// Encapsulates to this public key and returns ciphertext plus shared secret.
        public func encapsulate() throws -> (ciphertext: Data, sharedSecret: SymmetricKey) {
            try encapsulate(seed: randomBytes(count: encapsulationSeedBytes))
        }

        func encapsulate(seed: Data) throws -> (ciphertext: Data, sharedSecret: SymmetricKey) {
            guard seed.count == encapsulationSeedBytes else {
                throw MLKEMError.operationFailed
            }

            var ct = [UInt8](repeating: 0, count: ciphertextBytes)
            var ss = [UInt8](repeating: 0, count: sharedSecretBytes)
            let status = rawRepresentation.withUnsafeBytes { pkBytes in
                seed.withUnsafeBytes { seedBytes in
                    ct.withUnsafeMutableBytes { ctBytes in
                        ss.withUnsafeMutableBytes { ssBytes in
                            mlkem_native_swift_768_encapsulate_derand(
                                ctBytes.bindMemory(to: UInt8.self).baseAddress!,
                                ssBytes.bindMemory(to: UInt8.self).baseAddress!,
                                pkBytes.bindMemory(to: UInt8.self).baseAddress!,
                                seedBytes.bindMemory(to: UInt8.self).baseAddress!
                            )
                        }
                    }
                }
            }
            guard status == 0 else {
                throw MLKEMError.operationFailed
            }
            return (Data(ct), SymmetricKey(data: Data(ss)))
        }
    }

    private static func randomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw MLKEMError.randomGenerationFailed
        }
        return Data(bytes)
    }
}
