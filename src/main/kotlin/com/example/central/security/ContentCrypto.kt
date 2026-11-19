package com.example.central.security

/**
 * End-to-end content encryption: messages, group-key envelopes, payloads of
 * boards, trips and events. App: shared/src/commonMain/.../security/ContentCrypto.kt
 *
 * The FORMAT is part of the protocol and every platform must follow it,
 * otherwise Android and iOS can't read each other:
 * - AES-256-GCM, 128-bit tag, random 12-byte IV;
 * - ciphertext and IV in standard Base64 (RFC 4648, with padding);
 * - texts are UTF-8.
 */
interface ContentCrypto {
    /** Encrypts a text; returns (ciphertextBase64, ivBase64). */
    fun encrypt(plaintext: String, sharedKey: ByteArray): Pair<String, String>

    /** Like [encrypt], on raw bytes (group keys are not valid UTF-8). */
    fun encryptBytes(plaintext: ByteArray, sharedKey: ByteArray): Pair<String, String>

    /** Decrypts raw bytes; null if it doesn't decrypt, instead of throwing. */
    fun decryptBytes(ciphertextBase64: String, ivBase64: String, sharedKey: ByteArray): ByteArray?

    /** Decrypts a text; if it doesn't decrypt, a placeholder instead of an error. */
    fun decrypt(ciphertextBase64: String, ivBase64: String, sharedKey: ByteArray): String
}
