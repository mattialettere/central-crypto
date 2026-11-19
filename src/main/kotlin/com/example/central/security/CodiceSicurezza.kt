package com.example.central.security

import kotlin.io.encoding.Base64

/**
 * The safety number of a one-to-one chat ("codice di sicurezza"), like
 * WhatsApp's and Signal's. App: shared/src/commonMain/.../security/CodiceSicurezza.kt
 *
 * It defends against the attack encryption alone can't see: someone (with a
 * stolen token, or the server itself) replaces a person's public key on the
 * server with their own. Messages stay encrypted, but to the wrong key. The
 * two people compare this number, out loud or with the QR code: if it
 * matches, each really has the other's key.
 *
 * Algorithm (Signal's "numeric fingerprint", version 0, with the raw 32-byte
 * X25519 key instead of Signal's key with the 0x05 type byte):
 *
 * - for each person: h = 0x0000 || key || user id (UTF-8), then
 *   5,200 times h = SHA-512(h || key);
 * - 30 of the final 64 bytes are used: six 5-byte groups, each read as a
 *   big-endian integer, modulo 100,000, written as 5 digits;
 * - the two 30-digit halves are sorted (string comparison) and joined:
 *   60 digits, identical on both phones.
 *
 * All in common Kotlin (SHA-512 included), so Android and iPhone run the same
 * code; the vectors in testvectors/e2e-vectors.json, computed in Python with
 * hashlib, confirm it.
 */
object CodiceSicurezza {

    const val ITERAZIONI = 5_200
    const val CIFRE = 60

    /** QR content prefix: tells Central's code apart from any other QR. */
    const val PREFISSO_QR = "CENTRAL-SN1:"

    private val VERSIONE = byteArrayOf(0, 0)

    /** One person's 30 digits. */
    fun impronta(chiavePubblica: ByteArray, idUtente: String): String {
        require(chiavePubblica.size == 32) { "X25519 key of ${chiavePubblica.size} bytes instead of 32" }
        var h = VERSIONE + chiavePubblica + idUtente.encodeToByteArray()
        repeat(ITERAZIONI) { h = Sha512.digest(h + chiavePubblica) }
        return buildString {
            for (gruppo in 0 until 6) {
                var n = 0L
                for (i in 0 until 5) n = (n shl 8) or (h[gruppo * 5 + i].toLong() and 0xFF)
                append((n % 100_000).toString().padStart(5, '0'))
            }
        }
    }

    /**
     * The 60 digits of the chat between two people; the same value whoever
     * computes it. Null if either key isn't a valid X25519 key.
     */
    fun calcola(idA: String, chiaveABase64: String, idB: String, chiaveBBase64: String): String? {
        val a = decodifica(chiaveABase64) ?: return null
        val b = decodifica(chiaveBBase64) ?: return null
        val ia = impronta(a, idA)
        val ib = impronta(b, idB)
        return if (ia <= ib) ia + ib else ib + ia
    }

    /** 12 groups of 5 digits, as shown and read aloud. */
    fun gruppi(codice: String): List<String> = codice.chunked(5)

    fun contenutoQr(codice: String): String = PREFISSO_QR + codice

    /** The 60 digits read from a Central QR code, or null if it's another QR. */
    fun daQr(testo: String): String? {
        val t = testo.trim()
        if (!t.startsWith(PREFISSO_QR)) return null
        val cifre = t.removePrefix(PREFISSO_QR)
        return cifre.takeIf { it.length == CIFRE && it.all(Char::isDigit) }
    }

    /** Compares the text of a scanned QR code with our [codice]. */
    fun confronta(codice: String, testoQr: String): EsitoScansione {
        val letto = daQr(testoQr) ?: return EsitoScansione.NON_E_UN_CODICE
        return if (letto == codice) EsitoScansione.COINCIDE else EsitoScansione.NON_COINCIDE
    }

    private fun decodifica(base64: String): ByteArray? =
        runCatching { Base64.Mime.decode(base64) }.getOrNull()?.takeIf { it.size == 32 }
}

/** State of the safety-number verification with a contact. */
enum class StatoVerifica {
    NON_VERIFICATO,
    VERIFICATO,

    /** Verified in the past, but the contact's key is now a different one. */
    CAMBIATO,
}

/** The safety number of a one-to-one chat and its verification state. */
data class InfoCodiceSicurezza(
    /** The 60 digits. */
    val codice: String,
    val contattoId: String,
    /** The contact key it was computed with (the one to remember as verified). */
    val chiaveContatto: String,
    val stato: StatoVerifica,
)

/** Result of comparing with the QR code scanned on the other phone. */
enum class EsitoScansione { COINCIDE, NON_COINCIDE, NON_E_UN_CODICE }

/**
 * SHA-512 (FIPS 180-4) in pure Kotlin: common code has no hash library, and
 * this way Android and iPhone run exactly the same bytes. Checked against
 * java.security.MessageDigest in the tests.
 */
internal object Sha512 {
    private val K = longArrayOf(
        0x428a2f98d728ae22uL.toLong(), 0x7137449123ef65cduL.toLong(), 0xb5c0fbcfec4d3b2fuL.toLong(), 0xe9b5dba58189dbbcuL.toLong(),
        0x3956c25bf348b538uL.toLong(), 0x59f111f1b605d019uL.toLong(), 0x923f82a4af194f9buL.toLong(), 0xab1c5ed5da6d8118uL.toLong(),
        0xd807aa98a3030242uL.toLong(), 0x12835b0145706fbeuL.toLong(), 0x243185be4ee4b28cuL.toLong(), 0x550c7dc3d5ffb4e2uL.toLong(),
        0x72be5d74f27b896fuL.toLong(), 0x80deb1fe3b1696b1uL.toLong(), 0x9bdc06a725c71235uL.toLong(), 0xc19bf174cf692694uL.toLong(),
        0xe49b69c19ef14ad2uL.toLong(), 0xefbe4786384f25e3uL.toLong(), 0x0fc19dc68b8cd5b5uL.toLong(), 0x240ca1cc77ac9c65uL.toLong(),
        0x2de92c6f592b0275uL.toLong(), 0x4a7484aa6ea6e483uL.toLong(), 0x5cb0a9dcbd41fbd4uL.toLong(), 0x76f988da831153b5uL.toLong(),
        0x983e5152ee66dfabuL.toLong(), 0xa831c66d2db43210uL.toLong(), 0xb00327c898fb213fuL.toLong(), 0xbf597fc7beef0ee4uL.toLong(),
        0xc6e00bf33da88fc2uL.toLong(), 0xd5a79147930aa725uL.toLong(), 0x06ca6351e003826fuL.toLong(), 0x142929670a0e6e70uL.toLong(),
        0x27b70a8546d22ffcuL.toLong(), 0x2e1b21385c26c926uL.toLong(), 0x4d2c6dfc5ac42aeduL.toLong(), 0x53380d139d95b3dfuL.toLong(),
        0x650a73548baf63deuL.toLong(), 0x766a0abb3c77b2a8uL.toLong(), 0x81c2c92e47edaee6uL.toLong(), 0x92722c851482353buL.toLong(),
        0xa2bfe8a14cf10364uL.toLong(), 0xa81a664bbc423001uL.toLong(), 0xc24b8b70d0f89791uL.toLong(), 0xc76c51a30654be30uL.toLong(),
        0xd192e819d6ef5218uL.toLong(), 0xd69906245565a910uL.toLong(), 0xf40e35855771202auL.toLong(), 0x106aa07032bbd1b8uL.toLong(),
        0x19a4c116b8d2d0c8uL.toLong(), 0x1e376c085141ab53uL.toLong(), 0x2748774cdf8eeb99uL.toLong(), 0x34b0bcb5e19b48a8uL.toLong(),
        0x391c0cb3c5c95a63uL.toLong(), 0x4ed8aa4ae3418acbuL.toLong(), 0x5b9cca4f7763e373uL.toLong(), 0x682e6ff3d6b2b8a3uL.toLong(),
        0x748f82ee5defb2fcuL.toLong(), 0x78a5636f43172f60uL.toLong(), 0x84c87814a1f0ab72uL.toLong(), 0x8cc702081a6439ecuL.toLong(),
        0x90befffa23631e28uL.toLong(), 0xa4506cebde82bde9uL.toLong(), 0xbef9a3f7b2c67915uL.toLong(), 0xc67178f2e372532buL.toLong(),
        0xca273eceea26619cuL.toLong(), 0xd186b8c721c0c207uL.toLong(), 0xeada7dd6cde0eb1euL.toLong(), 0xf57d4f7fee6ed178uL.toLong(),
        0x06f067aa72176fbauL.toLong(), 0x0a637dc5a2c898a6uL.toLong(), 0x113f9804bef90daeuL.toLong(), 0x1b710b35131c471buL.toLong(),
        0x28db77f523047d84uL.toLong(), 0x32caab7b40c72493uL.toLong(), 0x3c9ebe0a15c9bebcuL.toLong(), 0x431d67c49c100d4cuL.toLong(),
        0x4cc5d4becb3e42b6uL.toLong(), 0x597f299cfc657e2auL.toLong(), 0x5fcb6fab3ad6faecuL.toLong(), 0x6c44198c4a475817uL.toLong(),
    )

    private val H0 = longArrayOf(
        0x6a09e667f3bcc908uL.toLong(), 0xbb67ae8584caa73buL.toLong(), 0x3c6ef372fe94f82buL.toLong(), 0xa54ff53a5f1d36f1uL.toLong(),
        0x510e527fade682d1uL.toLong(), 0x9b05688c2b3e6c1fuL.toLong(), 0x1f83d9abfb41bd6buL.toLong(), 0x5be0cd19137e2179uL.toLong(),
    )

    private fun Long.rotr(n: Int): Long = (this ushr n) or (this shl (64 - n))

    fun digest(dati: ByteArray): ByteArray {
        // Padding: 0x80, zeros, bit length as 128-bit big-endian.
        val lunghezzaBit = dati.size.toLong() * 8
        val totale = ((dati.size + 17 + 127) / 128) * 128
        val m = ByteArray(totale)
        dati.copyInto(m)
        m[dati.size] = 0x80.toByte()
        for (i in 0 until 8) m[totale - 1 - i] = (lunghezzaBit ushr (8 * i)).toByte()

        val h = H0.copyOf()
        val w = LongArray(80)
        for (blocco in 0 until totale / 128) {
            val base = blocco * 128
            for (t in 0 until 16) {
                var x = 0L
                for (i in 0 until 8) x = (x shl 8) or (m[base + t * 8 + i].toLong() and 0xFF)
                w[t] = x
            }
            for (t in 16 until 80) {
                val s0 = w[t - 15].rotr(1) xor w[t - 15].rotr(8) xor (w[t - 15] ushr 7)
                val s1 = w[t - 2].rotr(19) xor w[t - 2].rotr(61) xor (w[t - 2] ushr 6)
                w[t] = w[t - 16] + s0 + w[t - 7] + s1
            }
            var a = h[0]; var b = h[1]; var c = h[2]; var d = h[3]
            var e = h[4]; var f = h[5]; var g = h[6]; var hh = h[7]
            for (t in 0 until 80) {
                val s1 = e.rotr(14) xor e.rotr(18) xor e.rotr(41)
                val ch = (e and f) xor (e.inv() and g)
                val t1 = hh + s1 + ch + K[t] + w[t]
                val s0 = a.rotr(28) xor a.rotr(34) xor a.rotr(39)
                val maj = (a and b) xor (a and c) xor (b and c)
                val t2 = s0 + maj
                hh = g; g = f; f = e; e = d + t1
                d = c; c = b; b = a; a = t1 + t2
            }
            h[0] += a; h[1] += b; h[2] += c; h[3] += d
            h[4] += e; h[5] += f; h[6] += g; h[7] += hh
        }
        val out = ByteArray(64)
        for (i in 0 until 8) for (j in 0 until 8) out[i * 8 + j] = (h[i] ushr (56 - 8 * j)).toByte()
        return out
    }
}
