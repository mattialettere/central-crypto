package com.example.central.util

import com.google.crypto.tink.subtle.AesGcmJce
import com.google.crypto.tink.subtle.X25519
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * All of Central's Android cryptography, with no Android dependencies, so it
 * can be tested on a plain JVM.
 *
 * In the Android app this is app/src/main/java/com/example/central/util/CryptoCore.kt
 * (Tink "tink-android"; here the plain-JVM "tink" artifact, same API).
 *
 * Formats are fixed, bit for bit: standard Base64 without line breaks on
 * output; on input line breaks are accepted, as android.util.Base64 DEFAULT did.
 */
object CryptoCore {

    const val GCM_IV_LENGTH = 12
    const val GCM_TAG_LENGTH_BITS = 128
    const val PBKDF2_ITERATIONS = 210_000 // OWASP 2023+ for PBKDF2-HMAC-SHA256
    const val PBKDF2_KEY_LENGTH_BITS = 256
    const val SALT_LENGTH = 16
    const val GROUP_KEY_BYTES = 32 // AES-256

    private val encoder = Base64.getEncoder()
    private val decoder = Base64.getMimeDecoder()

    fun b64(bytes: ByteArray): String = encoder.encodeToString(bytes)
    fun daB64(testo: String): ByteArray = decoder.decode(testo)

    // ── AES-256-GCM (messages, group-key envelopes) ─────────────────────

    /**
     * Encrypts and returns (ciphertext, iv) in Base64.
     *
     * Tink produces [IV 12 bytes][ciphertext][tag 16 bytes]: the IV is split
     * off because the protocol carries it in a separate field.
     */
    fun cifra(testoInChiaro: ByteArray, chiave: ByteArray): Pair<String, String> {
        val cifrato = AesGcmJce(chiave).encrypt(testoInChiaro, null)
        val iv = cifrato.copyOfRange(0, GCM_IV_LENGTH)
        val corpo = cifrato.copyOfRange(GCM_IV_LENGTH, cifrato.size)
        return b64(corpo) to b64(iv)
    }

    /** Decrypts; throws if key, iv or data don't match. */
    fun decifra(ciphertextBase64: String, ivBase64: String, chiave: ByteArray): ByteArray {
        val iv = daB64(ivBase64)
        val corpo = daB64(ciphertextBase64)
        return AesGcmJce(chiave).decrypt(iv + corpo, null)
    }

    // ── X25519 ───────────────────────────────────────────────────────────

    fun nuovaChiavePrivata(): ByteArray = X25519.generatePrivateKey()

    fun chiavePubblica(privata: ByteArray): String = b64(X25519.publicFromPrivate(privata))

    /**
     * Shared secret between our private key and the other person's public
     * key: X25519 ECDH, then SHA-256, giving 32 bytes used as the AES-256 key.
     * Same value on both sides; the basis of every one-to-one chat.
     */
    fun segretoCondiviso(privata: ByteArray, pubblicaAltroBase64: String): ByteArray {
        val condiviso = X25519.computeSharedSecret(privata, daB64(pubblicaAltroBase64))
        return MessageDigest.getInstance("SHA-256").digest(condiviso)
    }

    // ── Private-key backup protected by a passphrase ─────────────────────

    fun chiaveDaPassphrase(passphrase: String, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(passphrase.toCharArray(), salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH_BITS)
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
    }

    fun cifraBackup(
        privata: ByteArray,
        passphrase: String,
        salt: ByteArray = ByteArray(SALT_LENGTH).also { SecureRandom().nextBytes(it) },
        iv: ByteArray = ByteArray(GCM_IV_LENGTH).also { SecureRandom().nextBytes(it) },
    ): KeyBackupPayload {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(chiaveDaPassphrase(passphrase, salt), "AES"),
            GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv),
        )
        return KeyBackupPayload(
            ciphertextBase64 = b64(cipher.doFinal(privata)),
            ivBase64 = b64(iv),
            saltBase64 = b64(salt),
        )
    }

    /**
     * Opens the backup. With the wrong passphrase it throws
     * AEADBadTagException: corrupted data is NEVER returned silently, because
     * a wrong private key saved on the phone would make everything unreadable
     * with no error anywhere.
     */
    fun decifraBackup(backup: KeyBackupPayload, passphrase: String): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(chiaveDaPassphrase(passphrase, daB64(backup.saltBase64)), "AES"),
            GCMParameterSpec(GCM_TAG_LENGTH_BITS, daB64(backup.ivBase64)),
        )
        return cipher.doFinal(daB64(backup.ciphertextBase64))
    }

    // ── Group keys ──────────────────────────────────────────────────────

    fun nuovaChiaveGruppo(): ByteArray =
        ByteArray(GROUP_KEY_BYTES).also { SecureRandom().nextBytes(it) }

    /**
     * Highest version among stored names ("<prefix>3", "<prefix>12"...).
     * Versions can have gaps (lost envelopes, skipped rotations) and names
     * must not be compared as text: "12" sorts before "3".
     */
    fun versioneMassima(nomi: Collection<String>, prefisso: String): Int =
        nomi.asSequence()
            .filter { it.startsWith(prefisso) }
            .mapNotNull { it.removePrefix(prefisso).toIntOrNull() }
            .maxOrNull() ?: 0
}
