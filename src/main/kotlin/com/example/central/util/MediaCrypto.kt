package com.example.central.util

import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.CipherOutputStream
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Encryption of private media (photos, videos, voice notes, files, SOS
 * videos, board images). Android app: app/src/main/java/com/example/central/util/MediaCrypto.kt
 *
 * Why message encryption is not enough: text travels E2E encrypted, but a
 * photo blob stored in a bucket would otherwise be readable by anyone with
 * the URL or storage access. From the app's side only ciphertext is uploaded.
 *
 * Encrypted file format
 * ─────────────────────
 *   "CEMD" (4) | version (1) | keyId (4) | salt (16) | iv (12) | ciphertext+tag
 *
 * • keyId — fingerprint of the conversation key, NOT the key: it only tells
 *           which key we already hold opens this file, without trying them
 *           all. On its own it reveals nothing (truncated SHA-256 of a 32-byte
 *           secret).
 * • salt  — from it and the conversation key, HKDF derives a different key for
 *           every single file. The chat key is never used directly on tens
 *           of megabytes, and two files never share key material.
 * • iv    — GCM nonce, random per file.
 * • The whole header is passed as AAD: modifying it (for example swapping the
 *   salt of two files) makes tag verification fail.
 *
 * Everything is streamed: a 50 MB video is never fully held in memory.
 */
object MediaCrypto {

    private val MAGIC = byteArrayOf(0x43, 0x45, 0x4D, 0x44) // "CEMD"
    private const val VERSION: Byte = 1

    private const val KEY_ID_LENGTH = 4
    private const val SALT_LENGTH = 16
    private const val IV_LENGTH = 12
    private const val TAG_BITS = 128
    private const val KEY_BYTES = 32

    /** 4 + 1 + 4 + 16 + 12 */
    const val HEADER_SIZE = 37

    private const val HKDF_INFO = "central-media-v1"
    private const val KEY_ID_INFO = "central-media-key-id"
    private const val BUFFER_SIZE = 64 * 1024

    /** Random AES-256 key, for media that don't belong to a single conversation (SOS). */
    fun randomKey(): ByteArray = ByteArray(KEY_BYTES).also { SecureRandom().nextBytes(it) }

    /** Public fingerprint of a key: 4 bytes, enough to pick the right key. */
    fun keyIdHex(baseKey: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(KEY_ID_INFO.toByteArray(Charsets.UTF_8))
        val id = digest.digest(baseKey).copyOf(KEY_ID_LENGTH)
        return id.joinToString("") { "%02x".format(it) }
    }

    /** Header of an encrypted file, already parsed. */
    data class Header(
        val keyIdHex: String,
        val salt: ByteArray,
        val iv: ByteArray,
        val raw: ByteArray,
    )

    /** Reads the header, or null if the file isn't in our format (old, unencrypted media). */
    fun readHeader(file: File): Header? = runCatching {
        file.inputStream().use { readHeader(it) }
    }.getOrNull()

    private fun readHeader(input: InputStream): Header? {
        val raw = ByteArray(HEADER_SIZE)
        var read = 0
        while (read < HEADER_SIZE) {
            val n = input.read(raw, read, HEADER_SIZE - read)
            if (n < 0) return null
            read += n
        }
        for (i in MAGIC.indices) if (raw[i] != MAGIC[i]) return null
        if (raw[4] != VERSION) return null

        val keyId = raw.copyOfRange(5, 5 + KEY_ID_LENGTH)
        val salt = raw.copyOfRange(9, 9 + SALT_LENGTH)
        val iv = raw.copyOfRange(25, 25 + IV_LENGTH)
        return Header(
            keyIdHex = keyId.joinToString("") { "%02x".format(it) },
            salt = salt,
            iv = iv,
            raw = raw,
        )
    }

    /**
     * Reads plaintext [source] and writes to [destination] the encrypted blob
     * ready for upload. The input stream is NOT closed here.
     */
    fun encryptStream(source: InputStream, destination: OutputStream, baseKey: ByteArray) {
        val salt = ByteArray(SALT_LENGTH).also { SecureRandom().nextBytes(it) }
        val iv = ByteArray(IV_LENGTH).also { SecureRandom().nextBytes(it) }

        val header = ByteArray(HEADER_SIZE)
        System.arraycopy(MAGIC, 0, header, 0, 4)
        header[4] = VERSION
        System.arraycopy(hexToBytes(keyIdHex(baseKey)), 0, header, 5, KEY_ID_LENGTH)
        System.arraycopy(salt, 0, header, 9, SALT_LENGTH)
        System.arraycopy(iv, 0, header, 25, IV_LENGTH)

        destination.write(header)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(deriveFileKey(baseKey, salt), "AES"),
            GCMParameterSpec(TAG_BITS, iv),
        )
        cipher.updateAAD(header)

        // CipherOutputStream.close() writes the final tag: it must be closed,
        // and closing also closes destination (ours, so that's fine).
        CipherOutputStream(destination, cipher).use { out ->
            source.copyTo(out, BUFFER_SIZE)
        }
    }

    /**
     * Decrypts [source] into [destination].
     *
     * Throws if the key is wrong or the file was tampered with: the GCM tag is
     * verified when the stream is closed. The caller must delete
     * [destination] on exception — a half-written file must not stay in the
     * cache posing as valid content.
     */
    fun decryptFile(source: File, destination: File, baseKey: ByteArray) {
        source.inputStream().use { input ->
            val header = readHeader(input)
                ?: throw IllegalStateException("Media file not encrypted or unknown format")

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(deriveFileKey(baseKey, header.salt), "AES"),
                GCMParameterSpec(TAG_BITS, header.iv),
            )
            cipher.updateAAD(header.raw)

            // update() + doFinal() explicitly, not CipherInputStream or
            // CipherOutputStream: both can swallow the tag exception.
            // CipherInputStream just returns -1; the JDK's CipherOutputStream
            // ignores it in close() (Android's throws, but that's a platform
            // detail). Here doFinal() always throws AEADBadTagException when
            // the key is wrong or the file was tampered with.
            FileOutputStream(destination).use { out ->
                val buffer = ByteArray(BUFFER_SIZE)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    cipher.update(buffer, 0, n)?.let { out.write(it) }
                }
                out.write(cipher.doFinal())
            }
        }
    }

    // ── HKDF-SHA256 (extract + a single expand block: 32 bytes) ──

    private fun deriveFileKey(baseKey: ByteArray, salt: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(baseKey)

        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        mac.update(HKDF_INFO.toByteArray(Charsets.UTF_8))
        mac.update(1.toByte())
        return mac.doFinal().copyOf(KEY_BYTES)
    }

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { i ->
            ((Character.digit(hex[i * 2], 16) shl 4) + Character.digit(hex[i * 2 + 1], 16)).toByte()
        }
}
