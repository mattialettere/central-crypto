import CommonCrypto
import CryptoKit
import Foundation
import Shared

/// Le primitive crittografiche per il codice comune (CryptoPrimitives in
/// shared/src/nonAndroidMain/.../security/PortableCrypto.kt).
///
/// Il formato dei messaggi, dei backup e delle chiavi di gruppo lo decide il
/// codice Kotlin, uguale ad Android: qui ci sono solo AES-256-GCM, X25519,
/// SHA-256 e PBKDF2-HMAC-SHA256. Vanno verificate con gli stessi vettori di
/// PortableCryptoTest (RFC 7748): vedi iosApp/README.md.
final class CentralCrypto: CryptoPrimitives {

    func randomBytes(count: Int32) -> KotlinByteArray {
        var bytes = [UInt8](repeating: 0, count: Int(count))
        let esito = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        precondition(esito == errSecSuccess, "SecRandomCopyBytes fallita")
        return Data(bytes).kotlin
    }

    /// Ciphertext seguito dal tag da 16 byte, come Tink/javax su Android.
    func aesGcmEncrypt(key: KotlinByteArray, iv: KotlinByteArray, plaintext: KotlinByteArray) -> KotlinByteArray {
        let sealed = try! AES.GCM.seal(
            plaintext.data,
            using: SymmetricKey(data: key.data),
            nonce: try! AES.GCM.Nonce(data: iv.data)
        )
        return (sealed.ciphertext + sealed.tag).kotlin
    }

    func aesGcmDecrypt(key: KotlinByteArray, iv: KotlinByteArray, ciphertextAndTag: KotlinByteArray) throws -> KotlinByteArray {
        let tutto = ciphertextAndTag.data
        guard tutto.count >= 16 else { throw CentralCryptoError.datiTroppoCorti }
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: iv.data),
            ciphertext: tutto.prefix(tutto.count - 16),
            tag: tutto.suffix(16)
        )
        return try AES.GCM.open(box, using: SymmetricKey(data: key.data)).kotlin
    }

    func x25519PrivateKey() -> KotlinByteArray {
        Curve25519.KeyAgreement.PrivateKey().rawRepresentation.kotlin
    }

    func x25519PublicKey(privateKey: KotlinByteArray) throws -> KotlinByteArray {
        try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey.data).publicKey.rawRepresentation.kotlin
    }

    /// Il segreto grezzo: lo SHA-256 lo applica il codice comune, come CryptoCore.
    func x25519SharedSecret(privateKey: KotlinByteArray, publicKey: KotlinByteArray) throws -> KotlinByteArray {
        let privata = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey.data)
        let pubblica = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey.data)
        let segreto = try privata.sharedSecretFromKeyAgreement(with: pubblica)
        return segreto.withUnsafeBytes { Data($0) }.kotlin
    }

    func sha256(data: KotlinByteArray) -> KotlinByteArray {
        Data(SHA256.hash(data: data.data)).kotlin
    }

    /// CryptoKit non ha PBKDF2: CommonCrypto. La passphrase in UTF-8, come
    /// PBKDF2WithHmacSHA256 di Java.
    func pbkdf2Sha256(passphrase: String, salt: KotlinByteArray, iterations: Int32, keyLengthBytes: Int32) -> KotlinByteArray {
        let password = Array(passphrase.utf8)
        let sale = [UInt8](salt.data)
        var chiave = [UInt8](repeating: 0, count: Int(keyLengthBytes))
        let esito = password.withUnsafeBufferPointer { p in
            CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                UnsafeRawPointer(p.baseAddress!).assumingMemoryBound(to: Int8.self), p.count,
                sale, sale.count,
                CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                UInt32(iterations),
                &chiave, chiave.count
            )
        }
        precondition(esito == kCCSuccess, "PBKDF2 fallita")
        return Data(chiave).kotlin
    }

    func hmacSha256(key: KotlinByteArray, data: KotlinByteArray) -> KotlinByteArray {
        Data(HMAC<SHA256>.authenticationCode(for: data.data, using: SymmetricKey(data: key.data))).kotlin
    }

    /// I media (formato MediaCrypto): l'header intero e' autenticato come dati associati.
    func aesGcmEncryptAad(key: KotlinByteArray, iv: KotlinByteArray, plaintext: KotlinByteArray, aad: KotlinByteArray) -> KotlinByteArray {
        let sealed = try! AES.GCM.seal(
            plaintext.data,
            using: SymmetricKey(data: key.data),
            nonce: try! AES.GCM.Nonce(data: iv.data),
            authenticating: aad.data
        )
        return (sealed.ciphertext + sealed.tag).kotlin
    }

    func aesGcmDecryptAad(key: KotlinByteArray, iv: KotlinByteArray, ciphertextAndTag: KotlinByteArray, aad: KotlinByteArray) throws -> KotlinByteArray {
        let tutto = ciphertextAndTag.data
        guard tutto.count >= 16 else { throw CentralCryptoError.datiTroppoCorti }
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: iv.data),
            ciphertext: tutto.prefix(tutto.count - 16),
            tag: tutto.suffix(16)
        )
        return try AES.GCM.open(box, using: SymmetricKey(data: key.data), authenticating: aad.data).kotlin
    }
}

enum CentralCryptoError: Error {
    case datiTroppoCorti
}

// MARK: - Data <-> KotlinByteArray

extension Data {
    var kotlin: KotlinByteArray {
        let array = KotlinByteArray(size: Int32(count))
        for (i, b) in enumerated() {
            array.set(index: Int32(i), value: Int8(bitPattern: b))
        }
        return array
    }
}

extension KotlinByteArray {
    var data: Data {
        var bytes = [UInt8](repeating: 0, count: Int(size))
        for i in 0..<Int(size) {
            bytes[i] = UInt8(bitPattern: get(index: Int32(i)))
        }
        return Data(bytes)
    }
}
