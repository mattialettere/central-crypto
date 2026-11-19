package com.example.central.security

import com.example.central.util.KeyBackupPayload

/**
 * The device's encryption keys. App: shared/src/commonMain/.../security/KeyVault.kt.
 * Implementations: KeyManager on Android (EncryptedSharedPreferences, see
 * reference/android) and [PortableKeyVault] on iPhone (Keychain).
 */
interface KeyVault {
    fun hasLocalPrivateKey(userId: String): Boolean
    fun getOrCreatePrivateKey(userId: String): ByteArray
    /** First 12 characters of the Base64 public key: only for logs and diagnostics. */
    fun impronta(privateKey: ByteArray): String
    fun improntaLocale(userId: String): String?
    fun requirePrivateKey(userId: String): ByteArray
    fun getPublicKeyBase64(userId: String): String
    fun deriveSharedSecret(userId: String, theirPublicKeyBase64: String): ByteArray

    fun createEncryptedBackup(userId: String, passphrase: String): KeyBackupPayload
    fun restoreFromEncryptedBackup(userId: String, passphrase: String, backup: KeyBackupPayload)

    fun generateGroupKey(): ByteArray
    fun saveGroupKey(chatId: String, version: Int, key: ByteArray)
    fun getGroupKey(chatId: String, version: Int): ByteArray?
    fun hasGroupKey(chatId: String, version: Int): Boolean
    fun highestGroupKeyVersion(chatId: String): Int
    fun clearGroupKeys(chatId: String)
    fun clearAll()

    /**
     * The contact's public key (Base64) that user [mioId] verified with the
     * safety number; null if never verified. If the contact's current key is
     * different, the verification no longer holds and the chat warns
     * ([CodiceSicurezza]).
     */
    fun chiaveVerificata(mioId: String, contattoId: String): String? = null

    /** Remembers the verification of [chiavePubblica]; null removes it. */
    fun salvaChiaveVerificata(mioId: String, contattoId: String, chiavePubblica: String?) {}
}
