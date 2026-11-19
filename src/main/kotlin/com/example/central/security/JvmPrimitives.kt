package com.example.central.security

import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * [CryptoPrimitives] with javax.crypto (JDK 11+ for X25519). In the app this
 * lives in the JVM tests (shared/src/jvmTest/.../PortableCryptoTest.kt): it's
 * how the code the iPhone runs is tested without an iPhone. On iOS the same
 * interface is implemented with CryptoKit (reference/ios/CentralCrypto.swift).
 */
object JvmPrimitives : CryptoPrimitives {
    private val random = SecureRandom()
    private val x25519 = NamedParameterSpec.X25519

    override fun randomBytes(count: Int) = ByteArray(count).also { random.nextBytes(it) }

    override fun aesGcmEncrypt(key: ByteArray, iv: ByteArray, plaintext: ByteArray): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        }.doFinal(plaintext)

    override fun aesGcmDecrypt(key: ByteArray, iv: ByteArray, ciphertextAndTag: ByteArray): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        }.doFinal(ciphertextAndTag)

    override fun x25519PrivateKey(): ByteArray = randomBytes(32)

    // X25519(k, 9) is the public key.
    override fun x25519PublicKey(privateKey: ByteArray): ByteArray =
        x25519SharedSecret(privateKey, ByteArray(32).also { it[0] = 9 })

    override fun x25519SharedSecret(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        val kf = KeyFactory.getInstance("XDH")
        val priv = kf.generatePrivate(XECPrivateKeySpec(x25519, privateKey))
        val u = BigInteger(1, publicKey.reversedArray())
        val pub = kf.generatePublic(XECPublicKeySpec(x25519, u))
        return KeyAgreement.getInstance("XDH").apply { init(priv); doPhase(pub, true) }.generateSecret()
    }

    override fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    override fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(data)

    override fun aesGcmEncryptAad(key: ByteArray, iv: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv)); updateAAD(aad)
        }.doFinal(plaintext)

    override fun aesGcmDecryptAad(key: ByteArray, iv: ByteArray, ciphertextAndTag: ByteArray, aad: ByteArray): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv)); updateAAD(aad)
        }.doFinal(ciphertextAndTag)

    override fun pbkdf2Sha256(passphrase: String, salt: ByteArray, iterations: Int, keyLengthBytes: Int): ByteArray =
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(PBEKeySpec(passphrase.toCharArray(), salt, iterations, keyLengthBytes * 8)).encoded
}
