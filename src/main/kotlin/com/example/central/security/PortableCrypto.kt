package com.example.central.security

import com.example.central.data.local.KeyValueStore
import com.example.central.util.KeyBackupPayload
import kotlin.io.encoding.Base64

/**
 * The platform's basic cryptographic operations. On iOS they come from
 * CryptoKit (plus CommonCrypto for PBKDF2), written in Swift in the app
 * (reference/ios/CentralCrypto.swift); on the JVM, javax.crypto ([JvmPrimitives]).
 *
 * Everything else (message format, backup, group keys) lives in
 * [PortableContentCrypto] and [PortableKeyVault], identical to Android.
 * App: shared/src/nonAndroidMain/.../security/PortableCrypto.kt
 */
interface CryptoPrimitives {
    fun randomBytes(count: Int): ByteArray

    /** AES-256-GCM, 128-bit tag, no associated data: ciphertext followed by the tag. */
    fun aesGcmEncrypt(key: ByteArray, iv: ByteArray, plaintext: ByteArray): ByteArray

    /** The inverse of [aesGcmEncrypt]; throws if the tag doesn't verify. */
    @Throws(Exception::class)
    fun aesGcmDecrypt(key: ByteArray, iv: ByteArray, ciphertextAndTag: ByteArray): ByteArray

    /** A new X25519 private key (32 bytes). */
    fun x25519PrivateKey(): ByteArray

    /** The public key (32 bytes) of the private key. */
    @Throws(Exception::class)
    fun x25519PublicKey(privateKey: ByteArray): ByteArray

    /** The raw X25519 secret (32 bytes), before any derivation. */
    @Throws(Exception::class)
    fun x25519SharedSecret(privateKey: ByteArray, publicKey: ByteArray): ByteArray

    fun sha256(data: ByteArray): ByteArray

    /** PBKDF2-HMAC-SHA256. */
    fun pbkdf2Sha256(passphrase: String, salt: ByteArray, iterations: Int, keyLengthBytes: Int): ByteArray

    /** HMAC-SHA256 (for the media HKDF). */
    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray

    /** Like [aesGcmEncrypt], with associated data [aad] authenticated but not encrypted (media). */
    fun aesGcmEncryptAad(key: ByteArray, iv: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray

    /** The inverse of [aesGcmEncryptAad]; throws if the tag or [aad] don't match. */
    @Throws(Exception::class)
    fun aesGcmDecryptAad(key: ByteArray, iv: ByteArray, ciphertextAndTag: ByteArray, aad: ByteArray): ByteArray
}

// CryptoCore's constants (Android): they are part of the protocol.
private const val GCM_IV_LENGTH = 12
private const val PBKDF2_ITERATIONS = 210_000
private const val PBKDF2_KEY_BYTES = 32
private const val SALT_LENGTH = 16
private const val GROUP_KEY_BYTES = 32

private fun b64(bytes: ByteArray): String = Base64.Default.encode(bytes)
// Like Base64.getMimeDecoder(): ignores line breaks and stray characters.
private fun daB64(testo: String): ByteArray = Base64.Mime.decode(testo)

/** The same format as CryptoManager/CryptoCore on Android. */
class PortableContentCrypto(private val p: CryptoPrimitives) : ContentCrypto {

    private fun cifra(chiaro: ByteArray, chiave: ByteArray): Pair<String, String> {
        val iv = p.randomBytes(GCM_IV_LENGTH)
        return b64(p.aesGcmEncrypt(chiave, iv, chiaro)) to b64(iv)
    }

    private fun decifra(ciphertextBase64: String, ivBase64: String, chiave: ByteArray): ByteArray =
        p.aesGcmDecrypt(chiave, daB64(ivBase64), daB64(ciphertextBase64))

    override fun encrypt(plaintext: String, sharedKey: ByteArray): Pair<String, String> =
        cifra(plaintext.encodeToByteArray(), sharedKey)

    override fun encryptBytes(plaintext: ByteArray, sharedKey: ByteArray): Pair<String, String> =
        cifra(plaintext, sharedKey)

    override fun decryptBytes(ciphertextBase64: String, ivBase64: String, sharedKey: ByteArray): ByteArray? =
        runCatching { decifra(ciphertextBase64, ivBase64, sharedKey) }.getOrNull()

    override fun decrypt(ciphertextBase64: String, ivBase64: String, sharedKey: ByteArray): String =
        runCatching { decifra(ciphertextBase64, ivBase64, sharedKey).decodeToString() }
            .getOrElse { NON_DECIFRABILE }

    companion object {
        /**
         * Shown instead of a message that can't be opened. In the app this is
         * a translated string resource; here a constant, the behaviour is the same.
         */
        const val NON_DECIFRABILE = "[message could not be decrypted]"
    }
}

/**
 * The device's encryption keys, with the same rules as KeyManager on
 * Android: one X25519 private key per user, group keys per version,
 * fingerprint = first 12 characters of the Base64 public key, backup with
 * PBKDF2-HMAC-SHA256 (210,000 iterations) and AES-256-GCM.
 *
 * [store] must be a protected store (on iOS the Keychain).
 */
class PortableKeyVault(
    private val p: CryptoPrimitives,
    private val store: KeyValueStore,
) : KeyVault {

    private fun storageKey(userId: String) = "$PRIVATE_KEY_PREFIX$userId"
    private fun groupStorageKey(chatId: String, version: Int) = "$GROUP_KEY_PREFIX${chatId}_v$version"

    private fun pubblica(privata: ByteArray): String = b64(p.x25519PublicKey(privata))

    override fun hasLocalPrivateKey(userId: String): Boolean = store.get(storageKey(userId)) != null

    override fun getOrCreatePrivateKey(userId: String): ByteArray {
        val key = storageKey(userId)
        store.get(key)?.let { return daB64(it) }

        val nuova = p.x25519PrivateKey()
        store.set(key, b64(nuova))
        // Read it back: better an error now than a published public key whose
        // private key doesn't exist. (The app also logs here; logging removed.)
        if (store.get(key) == null) {
            throw IllegalStateException("Could not save the encryption keys on this device")
        }
        return nuova
    }

    override fun impronta(privateKey: ByteArray): String = pubblica(privateKey).take(12)

    override fun improntaLocale(userId: String): String? = store.get(storageKey(userId))?.let { impronta(daB64(it)) }

    override fun requirePrivateKey(userId: String): ByteArray {
        val salvata = store.get(storageKey(userId))
            ?: throw IllegalStateException("Encryption keys are not set up on this device")
        return daB64(salvata)
    }

    override fun getPublicKeyBase64(userId: String): String = pubblica(requirePrivateKey(userId))

    /** X25519 ECDH then SHA-256: the AES-256 key of one-to-one chats. */
    override fun deriveSharedSecret(userId: String, theirPublicKeyBase64: String): ByteArray =
        p.sha256(p.x25519SharedSecret(requirePrivateKey(userId), daB64(theirPublicKeyBase64)))

    override fun createEncryptedBackup(userId: String, passphrase: String): KeyBackupPayload {
        val salt = p.randomBytes(SALT_LENGTH)
        val iv = p.randomBytes(GCM_IV_LENGTH)
        val chiave = p.pbkdf2Sha256(passphrase, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_BYTES)
        return KeyBackupPayload(
            ciphertextBase64 = b64(p.aesGcmEncrypt(chiave, iv, requirePrivateKey(userId))),
            ivBase64 = b64(iv),
            saltBase64 = b64(salt),
        )
    }

    override fun restoreFromEncryptedBackup(userId: String, passphrase: String, backup: KeyBackupPayload) {
        val chiave = p.pbkdf2Sha256(passphrase, daB64(backup.saltBase64), PBKDF2_ITERATIONS, PBKDF2_KEY_BYTES)
        // With the wrong passphrase the GCM tag doesn't verify and this throws:
        // a wrong key is never saved silently.
        val privata = p.aesGcmDecrypt(chiave, daB64(backup.ivBase64), daB64(backup.ciphertextBase64))
        store.set(storageKey(userId), b64(privata))
        if (store.get(storageKey(userId)) == null) {
            throw IllegalStateException("Could not save the encryption keys on this device")
        }
    }

    override fun generateGroupKey(): ByteArray = p.randomBytes(GROUP_KEY_BYTES)

    override fun saveGroupKey(chatId: String, version: Int, key: ByteArray) =
        store.set(groupStorageKey(chatId, version), b64(key))

    override fun getGroupKey(chatId: String, version: Int): ByteArray? =
        store.get(groupStorageKey(chatId, version))?.let { runCatching { daB64(it) }.getOrNull() }

    override fun hasGroupKey(chatId: String, version: Int): Boolean = store.get(groupStorageKey(chatId, version)) != null

    /** Versions are compared as numbers: "12" comes after "3". */
    override fun highestGroupKeyVersion(chatId: String): Int {
        val prefisso = "$GROUP_KEY_PREFIX${chatId}_v"
        return store.keys().asSequence()
            .filter { it.startsWith(prefisso) }
            .mapNotNull { it.removePrefix(prefisso).toIntOrNull() }
            .maxOrNull() ?: 0
    }

    override fun clearGroupKeys(chatId: String) {
        val prefisso = "$GROUP_KEY_PREFIX${chatId}_v"
        store.keys().filter { it.startsWith(prefisso) }.forEach { store.set(it, null) }
    }

    override fun clearAll() = store.keys().forEach { store.set(it, null) }

    override fun chiaveVerificata(mioId: String, contattoId: String): String? =
        store.get(verifiedStorageKey(mioId, contattoId))

    override fun salvaChiaveVerificata(mioId: String, contattoId: String, chiavePubblica: String?) =
        store.set(verifiedStorageKey(mioId, contattoId), chiavePubblica)

    private fun verifiedStorageKey(mioId: String, contattoId: String) = "$VERIFIED_KEY_PREFIX${mioId}_$contattoId"

    private companion object {
        const val PRIVATE_KEY_PREFIX = "e2ee_private_key_"
        const val GROUP_KEY_PREFIX = "e2ee_group_key_"
        // Contact's key verified with the safety number, per account.
        const val VERIFIED_KEY_PREFIX = "e2ee_verified_key_"
    }
}
