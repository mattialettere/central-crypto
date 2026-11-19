package com.example.central.util

import com.example.central.security.ContentCrypto
import javax.inject.Inject
import javax.inject.Singleton
import com.example.central.i18n.tr
import net.getcentral.central.R

/**
 * Cifratura AES-256-GCM dei messaggi e delle buste di gruppo.
 *
 * La crittografia vera sta in [CryptoCore], senza dipendenze da Android e
 * coperta dai test in app/src/test: qui restano solo le due scelte
 * dell'app su come comportarsi quando qualcosa non si decifra.
 */
@Singleton
class CryptoManager @Inject constructor() : ContentCrypto {

    /** Cifra un testo; restituisce (ciphertextBase64, ivBase64). */
    override fun encrypt(plaintext: String, sharedKey: ByteArray): Pair<String, String> =
        CryptoCore.cifra(plaintext.toByteArray(Charsets.UTF_8), sharedKey)

    /**
     * Come encrypt(), ma su byte grezzi anziché su testo.
     *
     * Serve per le chiavi di gruppo: la chiave AES-256 condivisa viene cifrata
     * per ogni membro con il segreto ECDH a coppie, e trattarla come stringa
     * la corromperebbe (non è UTF-8 valido).
     */
    override fun encryptBytes(plaintext: ByteArray, sharedKey: ByteArray): Pair<String, String> =
        CryptoCore.cifra(plaintext, sharedKey)

    /**
     * Decifra byte grezzi. Ritorna null invece di lanciare: una busta di
     * gruppo non apribile non deve far saltare la sincronizzazione delle
     * altre versioni (e chi chiama la segnala, vedi GroupRepository).
     */
    override fun decryptBytes(ciphertextBase64: String, ivBase64: String, sharedKey: ByteArray): ByteArray? =
        runCatching { CryptoCore.decifra(ciphertextBase64, ivBase64, sharedKey) }.getOrNull()

    /** Decifra un testo; se non si decifra, un segnaposto invece di un errore. */
    override fun decrypt(ciphertextBase64: String, ivBase64: String, sharedKey: ByteArray): String =
        runCatching {
            String(CryptoCore.decifra(ciphertextBase64, ivBase64, sharedKey), Charsets.UTF_8)
        }.getOrElse { NON_DECIFRABILE }

    companion object {
        /** Testo mostrato al posto di un messaggio che non si riesce ad aprire. */
        val NON_DECIFRABILE: String get() = tr(R.string.crypto_messaggio_non_decifrabile)
    }
}
