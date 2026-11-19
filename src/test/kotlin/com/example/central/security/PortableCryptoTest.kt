package com.example.central.security

import com.example.central.data.local.MemoryKeyValueStore
import java.math.BigInteger
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/**
 * Le regole crittografiche usate su iOS (PortableContentCrypto e
 * PortableKeyVault) sopra primitive javax.crypto: vettori di RFC 7748 per
 * X25519 e il formato di CryptoCore su Android (AES-GCM con IV a parte,
 * Base64 standard, backup PBKDF2). Le primitive Swift (CryptoKit) vanno
 * verificate sugli stessi vettori, vedi iosApp/README.
 */
class PortableCryptoTest {

    // Niente testi tradotti (ResourceTextSource): servono solo quando un
    // messaggio non si decifra, e caricarli chiede la risoluzione dello
    // schermo ad AWT, che senza display (Mac di Codemagic) lancia
    // HeadlessException. Questi test non passano mai da quei rami.

    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test
    fun x25519ComeRfc7748() {
        val aPriv = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val bPriv = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        assertContentEquals(hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"), JvmPrimitives.x25519PublicKey(aPriv))
        assertContentEquals(hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"), JvmPrimitives.x25519PublicKey(bPriv))
        assertContentEquals(
            hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
            JvmPrimitives.x25519SharedSecret(aPriv, JvmPrimitives.x25519PublicKey(bPriv)),
        )
    }

    /**
     * Vettori fissi, gli stessi di iosApp/iosAppTests/CentralCryptoTests.swift:
     * un messaggio cifrato (chiave 00..1f, IV 00..0b), la chiave di un backup
     * e la chiave di una chat a due (SHA-256 del segreto X25519 di RFC 7748).
     */
    @Test
    fun vettoriCondivisiConIos() {
        val crypto = PortableContentCrypto(JvmPrimitives)
        assertEquals(
            "Central è sicura 😀",
            crypto.decrypt("BGe4b7eErjtO6bf42IoNH+L2d6to+9ij+xFjgY9sc6FDmjBSn5U=", "AAECAwQFBgcICQoL", ByteArray(32) { it.toByte() }),
        )
        assertContentEquals(
            hex("bb7ced98972f58e73e8ad67ad951a583bd5bdfbcdf22fd474b781560601e6f86"),
            JvmPrimitives.pbkdf2Sha256("passphrase giusta", ByteArray(16) { it.toByte() }, 210_000, 32),
        )
        val vault = PortableKeyVault(JvmPrimitives, MemoryKeyValueStore().apply {
            set("e2ee_private_key_alice", Base64.getEncoder().encodeToString(hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")))
        })
        assertEquals(
            "3q1FodQ9aQKqkkC0PA11oLX8dQZgWQ1tRUYcv8QBBoQ=",
            Base64.getEncoder().encodeToString(
                vault.deriveSharedSecret("alice", Base64.getEncoder().encodeToString(hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")))
            ),
        )
    }

    @Test
    fun messaggiNelFormatoDiAndroid() {
        val crypto = PortableContentCrypto(JvmPrimitives)
        val chiave = ByteArray(32) { it.toByte() }
        val (testo, iv) = crypto.encrypt("ciao è 😀", chiave)
        // Come CryptoCore.decifra: IV e corpo (ciphertext+tag) separati, Base64 standard.
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(chiave, "AES"), GCMParameterSpec(128, Base64.getDecoder().decode(iv)))
        assertEquals("ciao è 😀", String(c.doFinal(Base64.getDecoder().decode(testo)), Charsets.UTF_8))
        assertEquals(12, Base64.getDecoder().decode(iv).size)
        // e al contrario
        val iv2 = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val e = Cipher.getInstance("AES/GCM/NoPadding")
        e.init(Cipher.ENCRYPT_MODE, SecretKeySpec(chiave, "AES"), GCMParameterSpec(128, iv2))
        val corpo = Base64.getEncoder().encodeToString(e.doFinal("dal telefono Android".toByteArray()))
        assertEquals("dal telefono Android", crypto.decrypt(corpo, Base64.getEncoder().encodeToString(iv2), chiave))
        assertNull(crypto.decryptBytes(corpo, Base64.getEncoder().encodeToString(iv2), ByteArray(32)))
    }

    @Test
    fun chiaviBackupEGruppi() {
        val vault = PortableKeyVault(JvmPrimitives, MemoryKeyValueStore())
        val privata = vault.getOrCreatePrivateKey("u1")
        assertContentEquals(privata, vault.getOrCreatePrivateKey("u1"))
        assertEquals(vault.getPublicKeyBase64("u1").take(12), vault.improntaLocale("u1"))

        val altro = PortableKeyVault(JvmPrimitives, MemoryKeyValueStore())
        altro.getOrCreatePrivateKey("u2")
        assertContentEquals(
            vault.deriveSharedSecret("u1", altro.getPublicKeyBase64("u2")),
            altro.deriveSharedSecret("u2", vault.getPublicKeyBase64("u1")),
        )

        val backup = vault.createEncryptedBackup("u1", "passphrase giusta")
        // Il backup si apre con PBKDF2WithHmacSHA256 come in CryptoCore.decifraBackup.
        val k = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(PBEKeySpec("passphrase giusta".toCharArray(), Base64.getDecoder().decode(backup.saltBase64), 210_000, 256)).encoded
        val d = Cipher.getInstance("AES/GCM/NoPadding")
        d.init(Cipher.DECRYPT_MODE, SecretKeySpec(k, "AES"), GCMParameterSpec(128, Base64.getDecoder().decode(backup.ivBase64)))
        assertContentEquals(privata, d.doFinal(Base64.getDecoder().decode(backup.ciphertextBase64)))

        val nuovo = PortableKeyVault(JvmPrimitives, MemoryKeyValueStore())
        assertFailsWith<Exception> { nuovo.restoreFromEncryptedBackup("u1", "sbagliata", backup) }
        nuovo.restoreFromEncryptedBackup("u1", "passphrase giusta", backup)
        assertEquals(vault.getPublicKeyBase64("u1"), nuovo.getPublicKeyBase64("u1"))

        vault.saveGroupKey("c", 3, ByteArray(32) { 1 })
        vault.saveGroupKey("c", 12, ByteArray(32) { 2 })
        assertEquals(12, vault.highestGroupKeyVersion("c"))
        vault.clearGroupKeys("c")
        assertEquals(0, vault.highestGroupKeyVersion("c"))
    }
}

// JvmPrimitives: in this repository it is in src/main (security/JvmPrimitives.kt).
