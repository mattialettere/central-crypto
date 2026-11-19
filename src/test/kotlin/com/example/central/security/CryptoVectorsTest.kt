package com.example.central.security

import com.example.central.data.local.MemoryKeyValueStore
import com.example.central.util.KeyBackupPayload
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.security.MessageDigest
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/**
 * Il codice comune che usa l'iPhone (PortableContentCrypto, PortableKeyVault,
 * MediaCryptoCodec) contro i vettori condivisi di testvectors/e2e-vectors.json.
 *
 * Gli stessi vettori li leggono anche app/src/test/.../CryptoVectorsTest.kt
 * (Android, Tink) e iosApp/iosAppTests/CryptoVectorsTests.swift (CryptoKit):
 * i valori attesi li ha calcolati una quarta implementazione, la libreria
 * Python cryptography (testvectors/genera_vettori.py).
 *
 * Qui i byte "casuali" (IV, sale) sono quelli dei vettori, cosi' anche la
 * cifratura si confronta byte per byte, non solo la decifratura.
 */
class CryptoVectorsTest {

    // Niente testi tradotti (ResourceTextSource): servono solo quando un
    // messaggio non si decifra, e caricarli chiede la risoluzione dello
    // schermo ad AWT, che senza display (Mac di Codemagic) lancia
    // HeadlessException. Questi test non passano mai da quei rami.

    private val v: JsonObject = caricaVettori()

    private fun JsonObject.s(nome: String) = getValue(nome).jsonPrimitive.content
    private fun JsonObject.b(nome: String): ByteArray = Base64.getDecoder().decode(s(nome))
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun b64(b: ByteArray) = Base64.getEncoder().encodeToString(b)

    @Test
    fun x25519EChiaveDellaChatADue() {
        val x = v.getValue("x25519").jsonObject
        val alice = hex(x.s("alice_private_hex"))
        val bob = hex(x.s("bob_private_hex"))
        assertEquals(x.s("alice_public_b64"), b64(JvmPrimitives.x25519PublicKey(alice)))
        assertEquals(x.s("bob_public_b64"), b64(JvmPrimitives.x25519PublicKey(bob)))
        assertContentEquals(hex(x.s("shared_raw_hex")), JvmPrimitives.x25519SharedSecret(alice, x.b("bob_public_b64")))

        val vaultAlice = PortableKeyVault(JvmPrimitives, MemoryKeyValueStore().apply { set("e2ee_private_key_a", b64(alice)) })
        val vaultBob = PortableKeyVault(JvmPrimitives, MemoryKeyValueStore().apply { set("e2ee_private_key_b", b64(bob)) })
        assertEquals(x.s("alice_public_b64"), vaultAlice.getPublicKeyBase64("a"))
        assertEquals(x.s("chat_key_b64"), b64(vaultAlice.deriveSharedSecret("a", x.s("bob_public_b64"))))
        assertEquals(x.s("chat_key_b64"), b64(vaultBob.deriveSharedSecret("b", x.s("alice_public_b64"))))
    }

    @Test
    fun messaggi() {
        for (m in v.getValue("messages").jsonArray.map { it.jsonObject }) {
            val nome = m.s("name")
            val chiave = m.b("key_b64")
            val lettore = PortableContentCrypto(JvmPrimitives)
            assertEquals(m.s("plaintext"), lettore.decrypt(m.s("ciphertext_b64"), m.s("iv_b64"), chiave), nome)

            val scrittore = PortableContentCrypto(PrimitiveConCasualiFissi(m.b("iv_b64")))
            val (cifrato, iv) = scrittore.encrypt(m.s("plaintext"), chiave)
            assertEquals(m.s("ciphertext_b64"), cifrato, nome)
            assertEquals(m.s("iv_b64"), iv, nome)

            // Un bit cambiato nel tag: niente testo, mai dati sbagliati.
            val alterato = m.b("ciphertext_b64").also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
            assertNull(lettore.decryptBytes(b64(alterato), m.s("iv_b64"), chiave), nome)
        }
    }

    @Test
    fun bustaDellaChiaveDiGruppo() {
        val e = v.getValue("group_key_envelope").jsonObject
        val (cifrato, iv) = PortableContentCrypto(PrimitiveConCasualiFissi(e.b("iv_b64")))
            .encryptBytes(e.b("group_key_b64"), e.b("pairwise_key_b64"))
        assertEquals(e.s("ciphertext_b64"), cifrato)
        assertEquals(e.s("iv_b64"), iv)
        assertContentEquals(
            e.b("group_key_b64"),
            PortableContentCrypto(JvmPrimitives).decryptBytes(e.s("ciphertext_b64"), e.s("iv_b64"), e.b("pairwise_key_b64")),
        )
    }

    @Test
    fun backupDellaChiavePrivata() {
        val k = v.getValue("key_backup").jsonObject
        assertEquals(
            k.s("derived_key_hex"),
            JvmPrimitives.pbkdf2Sha256(k.s("passphrase"), k.b("salt_b64"), k.getValue("iterations").jsonPrimitive.int, 32)
                .joinToString("") { "%02x".format(it) },
        )
        val vault = PortableKeyVault(
            PrimitiveConCasualiFissi(k.b("salt_b64"), k.b("iv_b64")),
            MemoryKeyValueStore().apply { set("e2ee_private_key_u", k.s("private_key_b64")) },
        )
        assertEquals(
            KeyBackupPayload(k.s("ciphertext_b64"), k.s("iv_b64"), k.s("salt_b64")),
            vault.createEncryptedBackup("u", k.s("passphrase")),
        )

        val backup = KeyBackupPayload(k.s("ciphertext_b64"), k.s("iv_b64"), k.s("salt_b64"))
        val nuovo = PortableKeyVault(JvmPrimitives, MemoryKeyValueStore())
        assertFailsWith<Exception> { nuovo.restoreFromEncryptedBackup("u", k.s("wrong_passphrase"), backup) }
        nuovo.restoreFromEncryptedBackup("u", k.s("passphrase"), backup)
        assertContentEquals(k.b("private_key_b64"), nuovo.requirePrivateKey("u"))
    }

    @Test
    fun media() {
        for (m in v.getValue("media").jsonArray.map { it.jsonObject }) {
            val nome = m.s("name")
            val chiave = m.b("base_key_b64")
            val chiaro = chiaroDelMedia(m)
            assertEquals(m.s("key_id_hex"), MediaCryptoCodec(JvmPrimitives).keyIdHex(chiave), nome)

            val blob = MediaCryptoCodec(PrimitiveConCasualiFissi(m.b("salt_b64"), m.b("iv_b64"))).encrypt(chiaro, chiave)
            assertEquals(m.getValue("blob_length").jsonPrimitive.int, blob.size, nome)
            assertEquals(m.s("blob_sha256_hex"), sha256Hex(blob), nome)
            assertEquals(m.s("header_hex"), blob.copyOf(37).joinToString("") { "%02x".format(it) }, nome)
            assertContentEquals(m.b("blob_b64"), blob, nome)

            assertContentEquals(chiaro, MediaCryptoCodec(JvmPrimitives).decrypt(m.b("blob_b64"), chiave), nome)
            val alterato = m.b("blob_b64").also { it[10] = (it[10].toInt() xor 1).toByte() } // il sale nell'header
            assertFailsWith<Exception>(nome) { MediaCryptoCodec(JvmPrimitives).decrypt(alterato, chiave) }
        }
    }

    @Test
    fun codiceDiSicurezza() {
        val sn = v.getValue("safety_numbers").jsonObject
        assertEquals(CodiceSicurezza.ITERAZIONI, sn.getValue("iterations").jsonPrimitive.int)
        assertEquals(CodiceSicurezza.PREFISSO_QR, sn.s("qr_prefix"))
        val casi = sn.getValue("cases").jsonArray.map { it.jsonObject }
        for (c in casi) {
            val nome = c.s("name")
            assertEquals(c.s("fingerprint_a"), CodiceSicurezza.impronta(c.b("public_a_b64"), c.s("user_a")), nome)
            assertEquals(c.s("fingerprint_b"), CodiceSicurezza.impronta(c.b("public_b_b64"), c.s("user_b")), nome)
            // Lo stesso codice dai due telefoni, in qualunque ordine.
            val daA = CodiceSicurezza.calcola(c.s("user_a"), c.s("public_a_b64"), c.s("user_b"), c.s("public_b_b64"))
            val daB = CodiceSicurezza.calcola(c.s("user_b"), c.s("public_b_b64"), c.s("user_a"), c.s("public_a_b64"))
            assertEquals(c.s("safety_number"), daA, nome)
            assertEquals(c.s("safety_number"), daB, nome)
            assertEquals(c.s("qr"), CodiceSicurezza.contenutoQr(c.s("safety_number")), nome)
            assertEquals(c.s("safety_number"), CodiceSicurezza.daQr(c.s("qr")), nome)
        }
        // La chiave sostituita cambia il codice: e' cosi' che si scopre.
        assert(casi[1].s("safety_number") != casi[2].s("safety_number"))
        assertNull(CodiceSicurezza.daQr("https://getcentral.net"))
        assertNull(CodiceSicurezza.daQr(CodiceSicurezza.PREFISSO_QR + "123"))
        assertNull(CodiceSicurezza.calcola("a", "non base64!", "b", casi[0].s("public_b_b64")))
    }

    @Test
    fun sha512ComeQuellaDiJava() {
        for (n in listOf(0, 1, 111, 112, 127, 128, 129, 255, 256, 1000)) {
            val dati = ByteArray(n) { (it * 7 + 3).toByte() }
            assertContentEquals(MessageDigest.getInstance("SHA-512").digest(dati), Sha512.digest(dati), "lunghezza $n")
        }
    }

    @Test
    fun chiaveVerificataPerAccount() {
        val vault = PortableKeyVault(JvmPrimitives, MemoryKeyValueStore())
        assertNull(vault.chiaveVerificata("io", "lei"))
        vault.salvaChiaveVerificata("io", "lei", "CHIAVE")
        assertEquals("CHIAVE", vault.chiaveVerificata("io", "lei"))
        // Un altro account sullo stesso telefono non eredita le verifiche.
        assertNull(vault.chiaveVerificata("altro", "lei"))
        vault.salvaChiaveVerificata("io", "lei", null)
        assertNull(vault.chiaveVerificata("io", "lei"))
    }

    private fun sha256Hex(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private fun chiaroDelMedia(m: JsonObject): ByteArray =
        m["plaintext_b64"]?.let { Base64.getDecoder().decode(it.jsonPrimitive.content) }
            ?: ByteArray(m.getValue("plaintext_pattern").jsonObject.getValue("length").jsonPrimitive.int) { i -> ((i * 31 + 7) % 251).toByte() }

    /** Le primitive JVM, ma i byte "casuali" sono quelli dati, nell'ordine. */
    private class PrimitiveConCasualiFissi(vararg fissi: ByteArray) : CryptoPrimitives by JvmPrimitives {
        private val coda = ArrayDeque(fissi.toList())
        override fun randomBytes(count: Int): ByteArray =
            coda.removeFirst().also { check(it.size == count) { "Attesi $count byte casuali, nel vettore ${it.size}" } }
    }

    companion object {
        /** testvectors/e2e-vectors.json, cercato dalla cartella del modulo in su. */
        fun caricaVettori(): JsonObject {
            var dir: File? = File(System.getProperty("user.dir")).absoluteFile
            while (dir != null) {
                val f = File(dir, "testvectors/e2e-vectors.json")
                if (f.isFile) return Json.parseToJsonElement(f.readText()).jsonObject
                dir = dir.parentFile
            }
            error("testvectors/e2e-vectors.json non trovato sopra ${System.getProperty("user.dir")}")
        }
    }
}
