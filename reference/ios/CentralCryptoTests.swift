import Shared
import XCTest
@testable import Central

/// Le primitive CryptoKit di CentralCrypto con gli stessi vettori di
/// shared/src/jvmTest/.../security/PortableCryptoTest.kt: se passano, iOS e
/// Android leggono gli stessi messaggi, backup e chat.
final class CentralCryptoTests: XCTestCase {
    private let crypto = CentralCrypto()

    private func hex(_ s: String) -> Data {
        var data = Data()
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            data.append(UInt8(s[i..<j], radix: 16)!)
            i = j
        }
        return data
    }

    func testX25519ComeRfc7748() throws {
        let aPriv = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").kotlin
        let bPriv = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb").kotlin
        XCTAssertEqual(try crypto.x25519PublicKey(privateKey: aPriv).data,
                       hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
        let bPub = try crypto.x25519PublicKey(privateKey: bPriv)
        XCTAssertEqual(bPub.data, hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
        XCTAssertEqual(try crypto.x25519SharedSecret(privateKey: aPriv, publicKey: bPub).data,
                       hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"))
    }

    func testMessaggioCifratoSuAndroid() {
        let contenuto = PortableContentCrypto(p: crypto)
        let chiave = Data(0..<32).kotlin
        XCTAssertEqual(
            contenuto.decrypt(ciphertextBase64: "BGe4b7eErjtO6bf42IoNH+L2d6to+9ij+xFjgY9sc6FDmjBSn5U=",
                              ivBase64: "AAECAwQFBgcICQoL", sharedKey: chiave),
            "Central è sicura 😀"
        )
        let cifrato = contenuto.encrypt(plaintext: "andata e ritorno", sharedKey: chiave)
        XCTAssertEqual(contenuto.decrypt(ciphertextBase64: cifrato.first as! String,
                                         ivBase64: cifrato.second as! String, sharedKey: chiave),
                       "andata e ritorno")
    }

    func testPbkdf2DelBackup() {
        XCTAssertEqual(
            crypto.pbkdf2Sha256(passphrase: "passphrase giusta", salt: Data(0..<16).kotlin,
                                iterations: 210_000, keyLengthBytes: 32).data,
            hex("bb7ced98972f58e73e8ad67ad951a583bd5bdfbcdf22fd474b781560601e6f86")
        )
    }

    func testGcmConTagSbagliatoLancia() {
        let chiave = Data(0..<32).kotlin
        let iv = Data(0..<12).kotlin
        let cifrato = crypto.aesGcmEncrypt(key: chiave, iv: iv, plaintext: Data("x".utf8).kotlin).data
        var alterato = cifrato
        alterato[alterato.count - 1] ^= 1
        XCTAssertThrowsError(try crypto.aesGcmDecrypt(key: chiave, iv: iv, ciphertextAndTag: alterato.kotlin))
    }
}
