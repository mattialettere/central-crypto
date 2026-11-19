package com.example.central.security

/**
 * The encrypted-media format of MediaCrypto (Android), for the other
 * platforms. App: shared/src/nonAndroidMain/.../security/MediaCryptoCodec.kt
 *
 *   "CEMD" (4) | version (1) | keyId (4) | salt (16) | iv (12) | ciphertext+tag
 *
 * - keyId: SHA-256("central-media-key-id" + key), first 4 bytes;
 * - file key: HKDF-SHA256(salt, key, "central-media-v1"), 32 bytes;
 * - AES-256-GCM with the whole header as associated data.
 *
 * Android encrypts as a stream; here it works in memory (media stay within a
 * few tens of MB). The result is the same format, byte for byte.
 */
class MediaCryptoCodec(private val p: CryptoPrimitives) {

    /** Parsed header. */
    class Header(val keyIdHex: String, val salt: ByteArray, val iv: ByteArray, val raw: ByteArray)

    fun keyIdHex(baseKey: ByteArray): String =
        p.sha256(KEY_ID_INFO.encodeToByteArray() + baseKey).copyOf(KEY_ID_LENGTH).toHex()

    /** The header, or null if the blob isn't in our format (old, unencrypted media). */
    fun readHeader(blob: ByteArray): Header? {
        if (blob.size < HEADER_SIZE) return null
        for (i in MAGIC.indices) if (blob[i] != MAGIC[i]) return null
        if (blob[4] != VERSION) return null
        return Header(
            keyIdHex = blob.copyOfRange(5, 9).toHex(),
            salt = blob.copyOfRange(9, 25),
            iv = blob.copyOfRange(25, 37),
            raw = blob.copyOfRange(0, HEADER_SIZE),
        )
    }

    fun encrypt(plain: ByteArray, baseKey: ByteArray): ByteArray {
        val salt = p.randomBytes(SALT_LENGTH)
        val iv = p.randomBytes(IV_LENGTH)
        val header = MAGIC + byteArrayOf(VERSION) + keyIdHex(baseKey).fromHex() + salt + iv
        return header + p.aesGcmEncryptAad(fileKey(baseKey, salt), iv, plain, header)
    }

    /** Throws if the key is wrong, the file was tampered with or isn't in the format. */
    fun decrypt(blob: ByteArray, baseKey: ByteArray): ByteArray {
        val header = readHeader(blob) ?: throw IllegalStateException("Media not encrypted or unknown format")
        return p.aesGcmDecryptAad(
            fileKey(baseKey, header.salt),
            header.iv,
            blob.copyOfRange(HEADER_SIZE, blob.size),
            header.raw,
        )
    }

    /** HKDF-SHA256: extract and a single expand block, like deriveFileKey on Android. */
    private fun fileKey(baseKey: ByteArray, salt: ByteArray): ByteArray {
        val prk = p.hmacSha256(salt, baseKey)
        return p.hmacSha256(prk, HKDF_INFO.encodeToByteArray() + byteArrayOf(1)).copyOf(KEY_BYTES)
    }

    private companion object {
        val MAGIC = byteArrayOf(0x43, 0x45, 0x4D, 0x44)
        const val VERSION: Byte = 1
        const val KEY_ID_LENGTH = 4
        const val SALT_LENGTH = 16
        const val IV_LENGTH = 12
        const val KEY_BYTES = 32
        const val HEADER_SIZE = 37
        const val HKDF_INFO = "central-media-v1"
        const val KEY_ID_INFO = "central-media-key-id"
    }
}

internal fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

internal fun String.fromHex(): ByteArray = ByteArray(length / 2) { i -> substring(i * 2, i * 2 + 2).toInt(16).toByte() }
