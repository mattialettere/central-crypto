import CryptoKit
import Shared
import XCTest
@testable import Central

/// CryptoKit (CentralCrypto) piu' il codice comune che usa l'iPhone
/// (PortableContentCrypto, PortableKeyVault, MediaCryptoCodec) contro i
/// vettori condivisi di testvectors/e2e-vectors.json.
///
/// Gli stessi vettori li leggono i test Android (app/src/test/.../
/// CryptoVectorsTest.kt, con Tink) e i test JVM del codice comune; i valori
/// attesi li calcola testvectors/genera_vettori.py con la libreria Python
/// cryptography. Qui IV e sale "casuali" sono quelli dei vettori, cosi' anche
/// la cifratura di CryptoKit si confronta byte per byte.
final class CryptoVectorsTests: XCTestCase {

    private var v: [String: Any] = [:]

    override func setUpWithError() throws {
        let url = try XCTUnwrap(
            Bundle(for: CryptoVectorsTests.self).url(forResource: "e2e-vectors", withExtension: "json"),
            "e2e-vectors.json non e' nel bundle dei test (iosApp/project.yml)"
        )
        v = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }

    // MARK: - Lettura dei vettori

    private func oggetto(_ nome: String) -> [String: Any] { v[nome] as! [String: Any] }
    private func lista(_ nome: String) -> [[String: Any]] { v[nome] as! [[String: Any]] }
    private func s(_ o: [String: Any], _ nome: String) -> String { o[nome] as! String }
    private func b(_ o: [String: Any], _ nome: String) -> Data { Data(base64Encoded: s(o, nome))! }
    private func n(_ o: [String: Any], _ nome: String) -> Int { (o[nome] as! NSNumber).intValue }

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

    private func esadecimale(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    private func chiaroDelMedia(_ m: [String: Any]) -> Data {
        if let chiaro = m["plaintext_b64"] as? String { return Data(base64Encoded: chiaro)! }
        let lunghezza = n(m["plaintext_pattern"] as! [String: Any], "length")
        return Data((0..<lunghezza).map { UInt8(($0 * 31 + 7) % 251) })
    }

    // MARK: - Test

    func testX25519EChiaveDellaChatADue() throws {
        let x = oggetto("x25519")
        let crypto = CentralCrypto()
        let alice = hex(s(x, "alice_private_hex"))
        let bob = hex(s(x, "bob_private_hex"))
        XCTAssertEqual(try crypto.x25519PublicKey(privateKey: alice.kotlin).data, b(x, "alice_public_b64"))
        XCTAssertEqual(try crypto.x25519PublicKey(privateKey: bob.kotlin).data, b(x, "bob_public_b64"))
        XCTAssertEqual(try crypto.x25519SharedSecret(privateKey: alice.kotlin, publicKey: b(x, "bob_public_b64").kotlin).data,
                       hex(s(x, "shared_raw_hex")))

        let store = MemoryKeyValueStore()
        store.set(key: "e2ee_private_key_a", value: alice.base64EncodedString())
        let vault = PortableKeyVault(p: crypto, store: store)
        XCTAssertEqual(vault.getPublicKeyBase64(userId: "a"), s(x, "alice_public_b64"))
        XCTAssertEqual(vault.deriveSharedSecret(userId: "a", theirPublicKeyBase64: s(x, "bob_public_b64")).data,
                       b(x, "chat_key_b64"))
    }

    func testMessaggi() {
        for m in lista("messages") {
            let nome = s(m, "name")
            let chiave = b(m, "key_b64").kotlin
            let lettore = PortableContentCrypto(p: CentralCrypto())
            XCTAssertEqual(lettore.decrypt(ciphertextBase64: s(m, "ciphertext_b64"), ivBase64: s(m, "iv_b64"), sharedKey: chiave),
                           s(m, "plaintext"), nome)

            let scrittore = PortableContentCrypto(p: PrimitiveConCasualiFissi(b(m, "iv_b64")))
            let cifrato = scrittore.encrypt(plaintext: s(m, "plaintext"), sharedKey: chiave)
            XCTAssertEqual(cifrato.first as? String, s(m, "ciphertext_b64"), nome)
            XCTAssertEqual(cifrato.second as? String, s(m, "iv_b64"), nome)

            var alterato = b(m, "ciphertext_b64")
            alterato[alterato.count - 1] ^= 1
            XCTAssertNil(lettore.decryptBytes(ciphertextBase64: alterato.base64EncodedString(), ivBase64: s(m, "iv_b64"), sharedKey: chiave), nome)
        }
    }

    func testBustaDellaChiaveDiGruppo() {
        let e = oggetto("group_key_envelope")
        let cifrato = PortableContentCrypto(p: PrimitiveConCasualiFissi(b(e, "iv_b64")))
            .encryptBytes(plaintext: b(e, "group_key_b64").kotlin, sharedKey: b(e, "pairwise_key_b64").kotlin)
        XCTAssertEqual(cifrato.first as? String, s(e, "ciphertext_b64"))
        XCTAssertEqual(cifrato.second as? String, s(e, "iv_b64"))
        XCTAssertEqual(PortableContentCrypto(p: CentralCrypto())
            .decryptBytes(ciphertextBase64: s(e, "ciphertext_b64"), ivBase64: s(e, "iv_b64"), sharedKey: b(e, "pairwise_key_b64").kotlin)?.data,
                       b(e, "group_key_b64"))
    }

    func testBackupDellaChiavePrivata() throws {
        let k = oggetto("key_backup")
        XCTAssertEqual(esadecimale(CentralCrypto().pbkdf2Sha256(passphrase: s(k, "passphrase"), salt: b(k, "salt_b64").kotlin,
                                                                 iterations: Int32(n(k, "iterations")), keyLengthBytes: 32).data),
                       s(k, "derived_key_hex"))

        let store = MemoryKeyValueStore()
        store.set(key: "e2ee_private_key_u", value: s(k, "private_key_b64"))
        let backup = PortableKeyVault(p: PrimitiveConCasualiFissi(b(k, "salt_b64"), b(k, "iv_b64")), store: store)
            .createEncryptedBackup(userId: "u", passphrase: s(k, "passphrase"))
        XCTAssertEqual(backup.ciphertextBase64, s(k, "ciphertext_b64"))
        XCTAssertEqual(backup.ivBase64, s(k, "iv_b64"))
        XCTAssertEqual(backup.saltBase64, s(k, "salt_b64"))

        let nuovo = PortableKeyVault(p: CentralCrypto(), store: MemoryKeyValueStore())
        nuovo.restoreFromEncryptedBackup(userId: "u", passphrase: s(k, "passphrase"),
                                         backup: KeyBackupPayload(ciphertextBase64: s(k, "ciphertext_b64"),
                                                                  ivBase64: s(k, "iv_b64"), saltBase64: s(k, "salt_b64")))
        XCTAssertEqual(nuovo.requirePrivateKey(userId: "u").data, b(k, "private_key_b64"))

        // Passphrase sbagliata: la chiave derivata non apre il backup (il tag non verifica).
        let sbagliata = CentralCrypto().pbkdf2Sha256(passphrase: s(k, "wrong_passphrase"), salt: b(k, "salt_b64").kotlin,
                                                     iterations: Int32(n(k, "iterations")), keyLengthBytes: 32)
        XCTAssertThrowsError(try CentralCrypto().aesGcmDecrypt(key: sbagliata, iv: b(k, "iv_b64").kotlin,
                                                               ciphertextAndTag: b(k, "ciphertext_b64").kotlin))
    }

    func testMedia() throws {
        for m in lista("media") {
            let nome = s(m, "name")
            let chiave = b(m, "base_key_b64").kotlin
            let chiaro = chiaroDelMedia(m)
            XCTAssertEqual(MediaCryptoCodec(p: CentralCrypto()).keyIdHex(baseKey: chiave), s(m, "key_id_hex"), nome)

            let blob = MediaCryptoCodec(p: PrimitiveConCasualiFissi(b(m, "salt_b64"), b(m, "iv_b64")))
                .encrypt(plain: chiaro.kotlin, baseKey: chiave).data
            XCTAssertEqual(blob.count, n(m, "blob_length"), nome)
            XCTAssertEqual(esadecimale(Data(SHA256.hash(data: blob))), s(m, "blob_sha256_hex"), nome)
            XCTAssertEqual(blob, b(m, "blob_b64"), nome)

            XCTAssertEqual(MediaCryptoCodec(p: CentralCrypto()).decrypt(blob: b(m, "blob_b64").kotlin, baseKey: chiave).data, chiaro, nome)

            // Header manomesso (il sale): con CryptoKit il tag non verifica.
            let header = b(m, "blob_b64").prefix(37)
            var sale = Data(header[9..<25])
            sale[0] ^= 1
            let prk = CentralCrypto().hmacSha256(key: sale.kotlin, data: chiave)
            let chiaveFile = CentralCrypto().hmacSha256(key: prk, data: (Data("central-media-v1".utf8) + [1]).kotlin).data.prefix(32)
            XCTAssertThrowsError(try CentralCrypto().aesGcmDecryptAad(
                key: Data(chiaveFile).kotlin, iv: Data(header[25..<37]).kotlin,
                ciphertextAndTag: b(m, "blob_b64").dropFirst(37).kotlin, aad: Data(header).kotlin), nome)
        }
    }

    /// Il codice di sicurezza (codice comune Kotlin compilato per iPhone):
    /// le stesse 60 cifre di Python e di Android, da entrambi i lati.
    func testCodiceDiSicurezza() {
        let sn = oggetto("safety_numbers")
        XCTAssertEqual(s(sn, "qr_prefix"), CodiceSicurezza.shared.PREFISSO_QR)
        let casi = sn["cases"] as! [[String: Any]]
        for c in casi {
            let nome = s(c, "name")
            XCTAssertEqual(CodiceSicurezza.shared.impronta(chiavePubblica: b(c, "public_a_b64").kotlin, idUtente: s(c, "user_a")),
                           s(c, "fingerprint_a"), nome)
            XCTAssertEqual(CodiceSicurezza.shared.calcola(idA: s(c, "user_a"), chiaveABase64: s(c, "public_a_b64"),
                                                          idB: s(c, "user_b"), chiaveBBase64: s(c, "public_b_b64")),
                           s(c, "safety_number"), nome)
            XCTAssertEqual(CodiceSicurezza.shared.calcola(idA: s(c, "user_b"), chiaveABase64: s(c, "public_b_b64"),
                                                          idB: s(c, "user_a"), chiaveBBase64: s(c, "public_a_b64")),
                           s(c, "safety_number"), nome)
            XCTAssertEqual(CodiceSicurezza.shared.daQr(testo: s(c, "qr")), s(c, "safety_number"), nome)
        }
        XCTAssertNotEqual(s(casi[1], "safety_number"), s(casi[2], "safety_number"))
    }

    /// Le verifiche fatte si ricordano per account, nel Portachiavi (PortableKeyVault).
    func testChiaveVerificata() {
        let vault = PortableKeyVault(p: CentralCrypto(), store: MemoryKeyValueStore())
        XCTAssertNil(vault.chiaveVerificata(mioId: "io", contattoId: "lei"))
        vault.salvaChiaveVerificata(mioId: "io", contattoId: "lei", chiavePubblica: "CHIAVE")
        XCTAssertEqual(vault.chiaveVerificata(mioId: "io", contattoId: "lei"), "CHIAVE")
        XCTAssertNil(vault.chiaveVerificata(mioId: "altro", contattoId: "lei"))
    }
}

/// CentralCrypto, ma i byte "casuali" (IV, sale) sono quelli dati, nell'ordine.
private final class PrimitiveConCasualiFissi: CryptoPrimitives {
    private let vere = CentralCrypto()
    private var coda: [Data]

    init(_ fissi: Data...) { coda = fissi }

    func randomBytes(count: Int32) -> KotlinByteArray {
        precondition(!coda.isEmpty && coda[0].count == Int(count), "Byte casuali fissi mancanti o di lunghezza sbagliata")
        return coda.removeFirst().kotlin
    }

    func aesGcmEncrypt(key: KotlinByteArray, iv: KotlinByteArray, plaintext: KotlinByteArray) -> KotlinByteArray {
        vere.aesGcmEncrypt(key: key, iv: iv, plaintext: plaintext)
    }

    func aesGcmDecrypt(key: KotlinByteArray, iv: KotlinByteArray, ciphertextAndTag: KotlinByteArray) throws -> KotlinByteArray {
        try vere.aesGcmDecrypt(key: key, iv: iv, ciphertextAndTag: ciphertextAndTag)
    }

    func x25519PrivateKey() -> KotlinByteArray { vere.x25519PrivateKey() }

    func x25519PublicKey(privateKey: KotlinByteArray) throws -> KotlinByteArray {
        try vere.x25519PublicKey(privateKey: privateKey)
    }

    func x25519SharedSecret(privateKey: KotlinByteArray, publicKey: KotlinByteArray) throws -> KotlinByteArray {
        try vere.x25519SharedSecret(privateKey: privateKey, publicKey: publicKey)
    }

    func sha256(data: KotlinByteArray) -> KotlinByteArray { vere.sha256(data: data) }

    func pbkdf2Sha256(passphrase: String, salt: KotlinByteArray, iterations: Int32, keyLengthBytes: Int32) -> KotlinByteArray {
        vere.pbkdf2Sha256(passphrase: passphrase, salt: salt, iterations: iterations, keyLengthBytes: keyLengthBytes)
    }

    func hmacSha256(key: KotlinByteArray, data: KotlinByteArray) -> KotlinByteArray { vere.hmacSha256(key: key, data: data) }

    func aesGcmEncryptAad(key: KotlinByteArray, iv: KotlinByteArray, plaintext: KotlinByteArray, aad: KotlinByteArray) -> KotlinByteArray {
        vere.aesGcmEncryptAad(key: key, iv: iv, plaintext: plaintext, aad: aad)
    }

    func aesGcmDecryptAad(key: KotlinByteArray, iv: KotlinByteArray, ciphertextAndTag: KotlinByteArray, aad: KotlinByteArray) throws -> KotlinByteArray {
        try vere.aesGcmDecryptAad(key: key, iv: iv, ciphertextAndTag: ciphertextAndTag, aad: aad)
    }
}
