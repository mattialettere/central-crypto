package com.example.central.util

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.Base64

/**
 * La crittografia di Android (CryptoCore con Tink, MediaCrypto) contro i
 * vettori condivisi di testvectors/e2e-vectors.json.
 *
 * Sono gli stessi che leggono il codice comune per iPhone
 * (shared/src/jvmTest/.../security/CryptoVectorsTest.kt) e l'app iOS con
 * CryptoKit (iosApp/iosAppTests/CryptoVectorsTests.swift). I valori attesi li
 * calcola testvectors/genera_vettori.py con la libreria Python cryptography:
 * se una libreria cambia un default, un test fallisce prima che qualcuno
 * smetta di leggere le proprie chat.
 *
 * CryptoCore.cifra e MediaCrypto.encryptStream scelgono IV e sale da soli:
 * per loro si controlla che il risultato si apra e abbia il formato giusto;
 * il confronto byte per byte della cifratura lo fanno backup (sale e IV
 * passati da fuori) e i test del codice comune.
 */
class CryptoVectorsTest {

    private val v: JsonObject = caricaVettori()

    private fun JsonObject.s(nome: String) = getValue(nome).jsonPrimitive.content
    private fun JsonObject.b(nome: String): ByteArray = Base64.getDecoder().decode(s(nome))
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test fun `x25519 e chiave della chat a due`() {
        val x = v.getValue("x25519").jsonObject
        val alice = hex(x.s("alice_private_hex"))
        val bob = hex(x.s("bob_private_hex"))
        assertEquals(x.s("alice_public_b64"), CryptoCore.chiavePubblica(alice))
        assertEquals(x.s("bob_public_b64"), CryptoCore.chiavePubblica(bob))
        assertEquals(x.s("chat_key_b64"), CryptoCore.b64(CryptoCore.segretoCondiviso(alice, x.s("bob_public_b64"))))
        assertEquals(x.s("chat_key_b64"), CryptoCore.b64(CryptoCore.segretoCondiviso(bob, x.s("alice_public_b64"))))
    }

    @Test fun `messaggi cifrati altrove si aprono, i nostri si aprono altrove`() {
        for (m in v.getValue("messages").jsonArray.map { it.jsonObject }) {
            val nome = m.s("name")
            val chiave = m.b("key_b64")
            assertEquals(nome, m.s("plaintext"),
                String(CryptoCore.decifra(m.s("ciphertext_b64"), m.s("iv_b64"), chiave), Charsets.UTF_8))

            // Il formato in uscita: IV da 12 byte a parte, corpo = testo + tag da 16.
            val (cifrato, iv) = CryptoCore.cifra(m.s("plaintext").toByteArray(Charsets.UTF_8), chiave)
            assertEquals(nome, 12, CryptoCore.daB64(iv).size)
            assertEquals(nome, m.b("ciphertext_b64").size, CryptoCore.daB64(cifrato).size)
            assertEquals(nome, m.s("plaintext"), String(CryptoCore.decifra(cifrato, iv, chiave), Charsets.UTF_8))

            val alterato = m.b("ciphertext_b64").also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
            assertFallisce(nome) { CryptoCore.decifra(CryptoCore.b64(alterato), m.s("iv_b64"), chiave) }
        }
    }

    @Test fun `busta della chiave di gruppo`() {
        val e = v.getValue("group_key_envelope").jsonObject
        assertArrayEquals(e.b("group_key_b64"), CryptoCore.decifra(e.s("ciphertext_b64"), e.s("iv_b64"), e.b("pairwise_key_b64")))
    }

    @Test fun `backup della chiave privata byte per byte`() {
        val k = v.getValue("key_backup").jsonObject
        assertEquals(k.s("derived_key_hex"),
            CryptoCore.chiaveDaPassphrase(k.s("passphrase"), k.b("salt_b64")).joinToString("") { "%02x".format(it) })
        assertEquals(k.getValue("iterations").jsonPrimitive.int, CryptoCore.PBKDF2_ITERATIONS)

        val backup = CryptoCore.cifraBackup(k.b("private_key_b64"), k.s("passphrase"), k.b("salt_b64"), k.b("iv_b64"))
        assertEquals(KeyBackupPayload(k.s("ciphertext_b64"), k.s("iv_b64"), k.s("salt_b64")), backup)
        assertArrayEquals(k.b("private_key_b64"), CryptoCore.decifraBackup(backup, k.s("passphrase")))
        assertFallisce("passphrase sbagliata") { CryptoCore.decifraBackup(backup, k.s("wrong_passphrase")) }
    }

    @Test fun `media cifrati altrove si aprono a flusso`() {
        val tmp = File(System.getProperty("java.io.tmpdir"))
        for (m in v.getValue("media").jsonArray.map { it.jsonObject }) {
            val nome = m.s("name")
            val chiave = m.b("base_key_b64")
            val chiaro = chiaroDelMedia(m)
            assertEquals(nome, m.s("key_id_hex"), MediaCrypto.keyIdHex(chiave))

            val sorgente = File.createTempFile("vettore", ".cemd", tmp).apply { writeBytes(m.b("blob_b64")) }
            val destinazione = File.createTempFile("vettore", ".bin", tmp)
            try {
                MediaCrypto.decryptFile(sorgente, destinazione, chiave)
                assertArrayEquals(nome, chiaro, destinazione.readBytes())

                // Il nostro blob: stesso header (salvo sale e IV), stessa lunghezza, si riapre.
                val uscita = ByteArrayOutputStream()
                MediaCrypto.encryptStream(ByteArrayInputStream(chiaro), uscita, chiave)
                val nostro = uscita.toByteArray()
                assertEquals(nome, m.getValue("blob_length").jsonPrimitive.int, nostro.size)
                assertEquals(nome, m.s("header_hex").substring(0, 18), nostro.copyOf(9).joinToString("") { "%02x".format(it) })
                sorgente.writeBytes(nostro)
                MediaCrypto.decryptFile(sorgente, destinazione, chiave)
                assertArrayEquals(nome, chiaro, destinazione.readBytes())

                // Header manomesso (il sale): il tag non verifica.
                sorgente.writeBytes(m.b("blob_b64").also { it[10] = (it[10].toInt() xor 1).toByte() })
                assertFallisce(nome) { MediaCrypto.decryptFile(sorgente, destinazione, chiave) }
            } finally {
                sorgente.delete()
                destinazione.delete()
            }
        }
    }

    /**
     * Il codice di sicurezza e' codice comune (CodiceSicurezza in :shared):
     * qui si controlla che, compilato per Android, dia le cifre di Python e
     * che le chiavi pubbliche di Tink (CryptoCore) diano lo stesso codice.
     */
    @Test
    fun codiceDiSicurezza() {
        val x = v.getValue("x25519").jsonObject
        assertEquals(x.s("alice_public_b64"), CryptoCore.chiavePubblica(hex(x.s("alice_private_hex"))))
        for (c in v.getValue("safety_numbers").jsonObject.getValue("cases").jsonArray.map { it.jsonObject }) {
            val nome = c.s("name")
            assertEquals(nome, c.s("fingerprint_a"), com.example.central.security.CodiceSicurezza.impronta(c.b("public_a_b64"), c.s("user_a")))
            assertEquals(nome, c.s("safety_number"),
                com.example.central.security.CodiceSicurezza.calcola(c.s("user_a"), c.s("public_a_b64"), c.s("user_b"), c.s("public_b_b64")))
            assertEquals(nome, c.s("safety_number"),
                com.example.central.security.CodiceSicurezza.calcola(c.s("user_b"), c.s("public_b_b64"), c.s("user_a"), c.s("public_a_b64")))
            assertEquals(nome, c.s("safety_number"), com.example.central.security.CodiceSicurezza.daQr(c.s("qr")))
        }
    }

    private fun chiaroDelMedia(m: JsonObject): ByteArray =
        m["plaintext_b64"]?.let { Base64.getDecoder().decode(it.jsonPrimitive.content) }
            ?: ByteArray(m.getValue("plaintext_pattern").jsonObject.getValue("length").jsonPrimitive.int) { i -> ((i * 31 + 7) % 251).toByte() }

    private fun assertFallisce(caso: String, blocco: () -> Unit) {
        try {
            blocco()
        } catch (e: Exception) {
            return
        }
        fail("Doveva fallire: $caso")
    }

    private fun caricaVettori(): JsonObject {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            val f = File(dir, "testvectors/e2e-vectors.json")
            if (f.isFile) return Json.parseToJsonElement(f.readText()).jsonObject
            dir = dir.parentFile
        }
        error("testvectors/e2e-vectors.json non trovato sopra ${System.getProperty("user.dir")}")
    }
}
