package com.example.central.util

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.MessageDigest
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Test della crittografia di Central.
 *
 * Girano su una normale JVM (./gradlew testDebugUnitTest), senza telefono.
 * Un errore qui non fa crashare l'app: rende illeggibili i messaggi. Per
 * questo ogni modifica a CryptoCore deve passare da questi test.
 */
class CryptoCoreTest {

    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)

    // Vettori ufficiali di X25519, RFC 7748 sezione 6.1.
    private val alicePriv = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    private val alicePub = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    private val bobPriv = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    private val bobPub = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    private val condivisoRfc = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

    // ── X25519 ───────────────────────────────────────────────────────────

    @Test fun `chiave pubblica coincide con il vettore RFC 7748`() {
        assertEquals(CryptoCore.b64(alicePub), CryptoCore.chiavePubblica(alicePriv))
        assertEquals(CryptoCore.b64(bobPub), CryptoCore.chiavePubblica(bobPriv))
    }

    @Test fun `segreto condiviso e lo SHA-256 del valore RFC 7748`() {
        val segreto = CryptoCore.segretoCondiviso(alicePriv, CryptoCore.b64(bobPub))
        assertArrayEquals(sha256(condivisoRfc), segreto)
        assertEquals(32, segreto.size)
    }

    @Test fun `segreto condiviso uguale nei due sensi`() {
        repeat(5) {
            val a = CryptoCore.nuovaChiavePrivata()
            val b = CryptoCore.nuovaChiavePrivata()
            assertArrayEquals(
                CryptoCore.segretoCondiviso(a, CryptoCore.chiavePubblica(b)),
                CryptoCore.segretoCondiviso(b, CryptoCore.chiavePubblica(a)),
            )
        }
    }

    @Test fun `terzi ottengono un segreto diverso`() {
        val a = CryptoCore.nuovaChiavePrivata()
        val b = CryptoCore.nuovaChiavePrivata()
        val c = CryptoCore.nuovaChiavePrivata()
        assertFalse(
            CryptoCore.segretoCondiviso(a, CryptoCore.chiavePubblica(b))
                .contentEquals(CryptoCore.segretoCondiviso(c, CryptoCore.chiavePubblica(b)))
        )
    }

    // ── AES-GCM ──────────────────────────────────────────────────────────

    private val chiave = ByteArray(32) { it.toByte() }

    @Test fun `andata e ritorno di un testo`() {
        val testo = "Ciao! Emoji 🎉 e accenti àèìòù, righe\nmultiple"
        val (ct, iv) = CryptoCore.cifra(testo.toByteArray(), chiave)
        assertEquals(testo, String(CryptoCore.decifra(ct, iv, chiave)))
        assertEquals(12, CryptoCore.daB64(iv).size)
    }

    @Test fun `andata e ritorno di byte e di un testo vuoto`() {
        val chiaveGruppo = CryptoCore.nuovaChiaveGruppo()
        val (ct, iv) = CryptoCore.cifra(chiaveGruppo, chiave)
        assertArrayEquals(chiaveGruppo, CryptoCore.decifra(ct, iv, chiave))
        val (ct2, iv2) = CryptoCore.cifra(ByteArray(0), chiave)
        assertEquals(0, CryptoCore.decifra(ct2, iv2, chiave).size)
    }

    @Test fun `ogni cifratura usa un iv nuovo`() {
        val a = CryptoCore.cifra("uguale".toByteArray(), chiave)
        val b = CryptoCore.cifra("uguale".toByteArray(), chiave)
        assertNotEquals(a.second, b.second)
        assertNotEquals(a.first, b.first)
    }

    @Test fun `formato compatibile con AES-GCM standard`() {
        // Cifrato con javax.crypto, indipendente da Tink: se il formato
        // (iv separato, tag in coda al ciphertext) cambiasse, i messaggi gia
        // salvati e quelli dei telefoni non aggiornati diventerebbero
        // illeggibili. Questo test lo impedisce.
        val iv = ByteArray(12) { (it * 7).toByte() }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(chiave, "AES"), GCMParameterSpec(128, iv))
        val ct = cipher.doFinal("messaggio".toByteArray())
        val testo = CryptoCore.decifra(CryptoCore.b64(ct), CryptoCore.b64(iv), chiave)
        assertEquals("messaggio", String(testo))
    }

    @Test fun `base64 senza a capo in uscita, a capo accettati in ingresso`() {
        val lungo = ByteArray(200) { it.toByte() }
        val (ct, iv) = CryptoCore.cifra(lungo, chiave)
        assertFalse(ct.contains('\n'))
        val conAcapo = ct.chunked(76).joinToString("\n") + "\n"
        assertArrayEquals(lungo, CryptoCore.decifra(conAcapo, iv, chiave))
    }

    @Test fun `chiave sbagliata non decifra`() {
        val (ct, iv) = CryptoCore.cifra("segreto".toByteArray(), chiave)
        val altra = ByteArray(32) { 9 }
        assertFallisce { CryptoCore.decifra(ct, iv, altra) }
    }

    @Test fun `dati alterati o iv scambiati non decifrano`() {
        val (ct, iv) = CryptoCore.cifra("segreto".toByteArray(), chiave)
        val alterato = CryptoCore.daB64(ct).also { it[0] = (it[0] + 1).toByte() }
        assertFallisce { CryptoCore.decifra(CryptoCore.b64(alterato), iv, chiave) }
        assertFallisce { CryptoCore.decifra(iv, ct, chiave) }
    }

    // (The app also tests CryptoManager here, the Android wrapper that shows a
    //  translated placeholder; it is not part of this repository.)

    // ── Backup della chiave privata ──────────────────────────────────────

    @Test fun `backup andata e ritorno con la passphrase giusta`() {
        val privata = CryptoCore.nuovaChiavePrivata()
        val backup = CryptoCore.cifraBackup(privata, "cavallo batteria graffetta")
        assertArrayEquals(privata, CryptoCore.decifraBackup(backup, "cavallo batteria graffetta"))
    }

    @Test fun `passphrase sbagliata lancia AEADBadTagException, mai dati corrotti`() {
        val backup = CryptoCore.cifraBackup(CryptoCore.nuovaChiavePrivata(), "giusta")
        try {
            CryptoCore.decifraBackup(backup, "sbagliata")
            fail("Una passphrase sbagliata deve fallire")
        } catch (e: AEADBadTagException) {
            // atteso
        }
    }

    @Test fun `backup deterministico a parita di sale e iv`() {
        val privata = ByteArray(32) { 3 }
        val sale = ByteArray(16) { 1 }
        val iv = ByteArray(12) { 2 }
        val a = CryptoCore.cifraBackup(privata, "pw", sale, iv)
        val b = CryptoCore.cifraBackup(privata, "pw", sale, iv)
        assertEquals(a, b)
        val c = CryptoCore.cifraBackup(privata, "pw", ByteArray(16) { 5 }, iv)
        assertNotEquals(a.ciphertextBase64, c.ciphertextBase64)
    }

    @Test fun `iterazioni PBKDF2 non abbassate`() {
        // Abbassarle renderebbe i backup piu facili da forzare, e cambiarle
        // renderebbe illeggibili quelli esistenti: in entrambi i casi il
        // test deve fallire e costringere a pensarci.
        assertEquals(210_000, CryptoCore.PBKDF2_ITERATIONS)
        assertEquals(256, CryptoCore.PBKDF2_KEY_LENGTH_BITS)
    }

    // ── Chiavi di gruppo ────────────────────────────────────────────────

    @Test fun `busta di gruppo apribile dal destinatario`() {
        val creatore = CryptoCore.nuovaChiavePrivata()
        val membro = CryptoCore.nuovaChiavePrivata()
        val chiaveGruppo = CryptoCore.nuovaChiaveGruppo()
        val (ct, iv) = CryptoCore.cifra(
            chiaveGruppo, CryptoCore.segretoCondiviso(creatore, CryptoCore.chiavePubblica(membro))
        )
        val aperta = CryptoCore.decifra(
            ct, iv, CryptoCore.segretoCondiviso(membro, CryptoCore.chiavePubblica(creatore))
        )
        assertArrayEquals(chiaveGruppo, aperta)
    }

    @Test fun `busta cifrata con una chiave non pubblicata non si apre`() {
        // Il guasto dei gruppi bloccati: il creatore cifra con una chiave
        // privata diversa da quella pubblicata, e chi riceve prova ad aprire
        // con la pubblicata. Deve fallire (ed e quello che fa partire la
        // segnalazione e la riparazione automatica).
        val pubblicata = CryptoCore.nuovaChiavePrivata()
        val usataDavvero = CryptoCore.nuovaChiavePrivata()
        val membro = CryptoCore.nuovaChiavePrivata()
        val (ct, iv) = CryptoCore.cifra(
            CryptoCore.nuovaChiaveGruppo(),
            CryptoCore.segretoCondiviso(usataDavvero, CryptoCore.chiavePubblica(membro)),
        )
        assertFallisce {
            CryptoCore.decifra(ct, iv, CryptoCore.segretoCondiviso(membro, CryptoCore.chiavePubblica(pubblicata)))
        }
    }

    @Test fun `chiavi di gruppo casuali da 32 byte`() {
        val a = CryptoCore.nuovaChiaveGruppo()
        assertEquals(32, a.size)
        assertFalse(a.contentEquals(CryptoCore.nuovaChiaveGruppo()))
    }

    @Test fun `versione massima con buchi e numeri a piu cifre`() {
        val p = "e2ee_group_key_chat1_v"
        val nomi = listOf("${p}1", "${p}3", "${p}12", "e2ee_group_key_chat2_v99", "${p}x", "altro")
        assertEquals(12, CryptoCore.versioneMassima(nomi, p))
        assertEquals(0, CryptoCore.versioneMassima(emptyList(), p))
        assertEquals(0, CryptoCore.versioneMassima(listOf("${p}abc"), p))
    }

    private fun assertFallisce(blocco: () -> Unit) {
        try {
            blocco()
        } catch (e: Exception) {
            return
        }
        fail("Doveva fallire")
    }

    @Test fun `assertFallisce funziona`() {
        var chiamato = false
        try { assertFallisce { chiamato = true } } catch (e: AssertionError) { assertTrue(chiamato); return }
        fail("assertFallisce non ha segnalato un blocco riuscito")
    }
}
