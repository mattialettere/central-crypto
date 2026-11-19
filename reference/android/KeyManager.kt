package com.example.central.util

import com.example.central.security.KeyVault
import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton
import com.example.central.i18n.tr
import net.getcentral.central.R

// KeyBackupPayload e la crittografia vera stanno in CryptoCore.kt, senza
// dipendenze da Android, per poterle verificare con i test su JVM.

// MESSAGE_TYPE_KEY_RESET sta nel modulo :shared (stesso package).

@Singleton
class KeyManager @Inject constructor(
    @ApplicationContext private val context: Context
) : KeyVault {
    companion object {
        private const val PREF_FILE = "secure_keys"
        private const val PRIVATE_KEY_PREFIX = "e2ee_private_key_"
        private const val GROUP_KEY_PREFIX = "e2ee_group_key_"
        // Chiave del contatto verificata con il codice di sicurezza, per account.
        private const val VERIFIED_KEY_PREFIX = "e2ee_verified_key_"

    }

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs by lazy { createPrefsRobustly() }

    private fun createPrefsRobustly(): SharedPreferences {
        return try {
            EncryptedSharedPreferences.create(
                context,
                PREF_FILE,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        } catch (e: Exception) {
            // ATTENZIONE: questo percorso CANCELLA le chiavi private E2E.
            //
            // E' un'uscita di emergenza per un file illeggibile, ma il
            // prezzo e' la perdita di tutte le conversazioni cifrate di
            // questo dispositivo. Se questa riga compare nei log senza che
            // l'utente abbia disinstallato l'app, e' la spiegazione di
            // qualunque "non riesco piu' a leggere niente": la schermata di
            // ripristino ricompare perche' la chiave e' sparita da qui, non
            // perche' l'utente abbia fatto qualcosa.
            Log.e("KeyManager", "CHIAVI E2E CANCELLATE: EncryptedSharedPreferences illeggibile", e)
            try {
                // Wipe the corrupted file
                context.getSharedPreferences(PREF_FILE, Context.MODE_PRIVATE).edit().clear().apply()
                
                // Also attempt to delete the physical file as an extra safety measure
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
                    context.deleteSharedPreferences(PREF_FILE)
                }
            } catch (e2: Exception) {
                Log.e("KeyManager", "Failed to wipe corrupted prefs", e2)
            }
            
            // Try again
            EncryptedSharedPreferences.create(
                context,
                PREF_FILE,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        }
    }

    // ───────────────────────────────────────────────
    // KEYPAIR LOCALE — scoping per utente
    // ───────────────────────────────────────────────
    // Ogni account ha la propria voce nello storage, così su un device usato
    // per testare più account (o dove un utente fa logout/login con un
    // account diverso) non si ritrova a riusare per sbaglio la keypair E2E
    // di un altro account già presente in EncryptedSharedPreferences.

    private fun storageKey(userId: String) = PRIVATE_KEY_PREFIX + userId

    /**
     * Ritorna true se esiste già una chiave privata su questo device
     * PER QUESTO SPECIFICO userId. Usato per decidere se serve rigenerarla
     * o proporre il ripristino da backup.
     */
    override fun hasLocalPrivateKey(userId: String): Boolean = prefs.getString(storageKey(userId), null) != null

    /**
     * Gets existing private key for this userId or generates a new one.
     * Private key is stored in EncryptedSharedPreferences, sotto una chiave
     * dedicata a questo account.
     */
    override fun getOrCreatePrivateKey(userId: String): ByteArray {
        val key = storageKey(userId)
        val stored = prefs.getString(key, null)
        if (stored != null) return Base64.decode(stored, Base64.DEFAULT)

        val newKey = CryptoCore.nuovaChiavePrivata()

        // commit() e non apply(): la scrittura deve essere finita PRIMA che
        // il chiamante pubblichi la chiave pubblica sul server.
        //
        // apply() scrive su un thread di sfondo e non dice se ce l'ha fatta.
        // Se il processo muore in quella finestra — o se la scrittura
        // fallisce — il server resta con una chiave pubblica di cui nessuno
        // ha piu' la privata: i messaggi diventano illeggibili in ENTRAMBE
        // le direzioni, per sempre, e non c'e' sincronizzazione che possa
        // rimediare, perche' dal punto di vista del server quella chiave e'
        // perfettamente valida. commit() blocca per qualche millisecondo una
        // volta nella vita dell'account: e' il prezzo giusto.
        val salvata = prefs.edit()
            .putString(key, Base64.encodeToString(newKey, Base64.DEFAULT))
            .commit()

        // E non ci si fida nemmeno di commit(): si rilegge. Meglio un errore
        // subito, con l'utente davanti allo schermo che puo' riprovare, che
        // una chiave pubblicata e una privata che non esiste.
        val riletta = prefs.getString(key, null)
        if (!salvata || riletta == null) {
            Log.e("KeyManager", "Chiave privata non persistita | user=$userId | commit=$salvata")
            throw IllegalStateException(
                tr(R.string.key_impossibile_salvare_chiavi_cifratura_su_ques)
            )
        }

        Log.i(
            "KeyManager",
            "Nuova coppia di chiavi generata | user=$userId | impronta=${impronta(newKey)}"
        )
        return newKey
    }

    /**
     * Prime cifre della chiave PUBBLICA derivata, per i log.
     *
     * Serve a confrontare in fretta cosa ha in mano ciascun dispositivo
     * quando qualcosa non si decifra: due impronte diverse per lo stesso
     * utente dicono in un colpo d'occhio dove sta lo scollamento. Non
     * espone nulla di segreto — la chiave pubblica e' pubblica per
     * definizione, e la privata non compare mai nei log.
     */
    override fun impronta(privateKey: ByteArray): String =
        CryptoCore.chiavePubblica(privateKey).take(12)

    /** Impronta della chiave pubblica di questo utente, per i log. */
    override fun improntaLocale(userId: String): String? =
        prefs.getString(storageKey(userId), null)
            ?.let { impronta(Base64.decode(it, Base64.DEFAULT)) }

    /**
     * Chiave privata esistente, oppure errore.
     *
     * Tutto cio che cifra o decifra passa da qui e NON crea chiavi: una
     * chiave nata in silenzio a meta dell'uso (perche quella vera mancava)
     * non verrebbe mai pubblicata, e ogni messaggio o chiave di gruppo
     * cifrato con lei sarebbe illeggibile per gli altri — senza che nessuno
     * se ne accorga. Le chiavi nuove nascono solo nella schermata della
     * passphrase ([getOrCreatePrivateKey] da AuthRepository), che le
     * pubblica subito.
     */
    override fun requirePrivateKey(userId: String): ByteArray {
        val stored = prefs.getString(storageKey(userId), null)
            ?: throw ChiaviNonConfigurate()
        return Base64.decode(stored, Base64.DEFAULT)
    }

    override fun getPublicKeyBase64(userId: String): String =
        CryptoCore.chiavePubblica(requirePrivateKey(userId))

    /**
     * Performs ECDH between our private key (di userId) e la public key del contatto.
     * Then applies SHA-256 to derive a 32-byte (256-bit) shared secret.
     */
    override fun deriveSharedSecret(userId: String, theirPublicKeyBase64: String): ByteArray =
        CryptoCore.segretoCondiviso(requirePrivateKey(userId), theirPublicKeyBase64)

    // ───────────────────────────────────────────────
    // BACKUP CIFRATO DELLA CHIAVE PRIVATA (account-bound E2E)
    // ───────────────────────────────────────────────

    /**
     * Cifra la chiave privata X25519 correntemente in uso con una chiave AES-256
     * derivata dalla passphrase di recupero scelta dall'utente (PBKDF2-HMAC-SHA256).
     * Il risultato va caricato sul backend via PUT /me/key-backup.
     *
     * Il server non riceve mai la passphrase né la chiave in chiaro: solo
     * ciphertext + iv + salt, tutti inutili senza la passphrase originale.
     */
    override fun createEncryptedBackup(userId: String, passphrase: String): KeyBackupPayload =
        CryptoCore.cifraBackup(requirePrivateKey(userId), passphrase)

    /**
     * Decifra un backup scaricato dal server usando la passphrase inserita
     * dall'utente, e salva la chiave privata risultante localmente su questo
     * device (così torna a funzionare come se non fosse mai stata reinstallata).
     *
     * Lancia un'eccezione se la passphrase è sbagliata (il tag GCM non verifica).
     * Il chiamante dovrebbe mostrare "passphrase errata, riprova" in quel caso.
     */
    override fun restoreFromEncryptedBackup(userId: String, passphrase: String, backup: KeyBackupPayload) {
        // Se la passphrase è sbagliata, questo lancia AEADBadTagException
        val privateKey = CryptoCore.decifraBackup(backup, passphrase)

        // commit() e riletta, come per la generazione: il chiamante subito
        // dopo pubblica la chiave pubblica, e deve essere sicuro che la
        // privata corrispondente sia davvero salvata.
        val salvata = prefs.edit()
            .putString(storageKey(userId), Base64.encodeToString(privateKey, Base64.DEFAULT))
            .commit()
        if (!salvata || prefs.getString(storageKey(userId), null) == null) {
            throw IllegalStateException(tr(R.string.key_impossibile_salvare_chiavi_cifratura_su_ques))
        }
    }

    // ───────────────────────────────────────────────
    // CHIAVI DI GRUPPO
    // ───────────────────────────────────────────────
    //
    // Nelle chat 1:1 la chiave si deriva al volo con ECDH e non va salvata.
    // Nei gruppi invece esiste UNA chiave simmetrica condivisa, ricevuta in
    // una busta cifrata: va conservata, e va conservata anche nelle versioni
    // vecchie, altrimenti lo storico diventa illeggibile dopo ogni aggiunta o
    // espulsione. Sta qui dentro, nelle EncryptedSharedPreferences, accanto
    // alla chiave privata: è materiale della stessa delicatezza.

    private fun groupStorageKey(chatId: String, version: Int) =
        "$GROUP_KEY_PREFIX${chatId}_v$version"

    /** Nuova chiave di gruppo AES-256 casuale. */
    override fun generateGroupKey(): ByteArray = CryptoCore.nuovaChiaveGruppo()

    override fun saveGroupKey(chatId: String, version: Int, key: ByteArray) {
        prefs.edit()
            .putString(groupStorageKey(chatId, version), Base64.encodeToString(key, Base64.NO_WRAP))
            .apply()
    }

    override fun getGroupKey(chatId: String, version: Int): ByteArray? {
        val stored = prefs.getString(groupStorageKey(chatId, version), null) ?: return null
        return runCatching { Base64.decode(stored, Base64.NO_WRAP) }.getOrNull()
    }

    override fun hasGroupKey(chatId: String, version: Int): Boolean =
        prefs.contains(groupStorageKey(chatId, version))

    /**
     * Versione più alta già in nostro possesso per questo gruppo.
     * Serve a chiedere al server solo le buste nuove invece di riscaricarle
     * tutte a ogni apertura della chat.
     */
    override fun highestGroupKeyVersion(chatId: String): Int {
        return CryptoCore.versioneMassima(prefs.all.keys, "$GROUP_KEY_PREFIX${chatId}_v")
    }

    /**
     * Cancella tutte le versioni di chiave di un gruppo.
     * Da chiamare quando si esce o si viene espulsi: da quel momento non
     * abbiamo più titolo per leggere niente di quel gruppo, e tenersi le
     * chiavi sarebbe solo materiale sensibile che resta lì per inerzia.
     */
    override fun clearGroupKeys(chatId: String) {
        val prefix = "$GROUP_KEY_PREFIX${chatId}_v"
        val editor = prefs.edit()
        prefs.all.keys.filter { it.startsWith(prefix) }.forEach { editor.remove(it) }
        editor.apply()
    }

    override fun clearAll() {
        prefs.edit().clear().apply()
    }

    // ───────────────────────────────────────────────
    // CODICE DI SICUREZZA VERIFICATO
    // ───────────────────────────────────────────────
    //
    // Si ricorda QUALE chiave del contatto e' stata verificata, non solo
    // "verificato si'/no": se la chiave cambia (reinstallazione, oppure
    // qualcuno l'ha sostituita sul server) la chat se ne accorge e avvisa.
    // Sta qui, cifrato, perche' chi potesse riscriverlo potrebbe far
    // sembrare verificata una chiave falsa.

    private fun verifiedStorageKey(mioId: String, contattoId: String) =
        "$VERIFIED_KEY_PREFIX${mioId}_$contattoId"

    override fun chiaveVerificata(mioId: String, contattoId: String): String? =
        prefs.getString(verifiedStorageKey(mioId, contattoId), null)

    override fun salvaChiaveVerificata(mioId: String, contattoId: String, chiavePubblica: String?) {
        val editor = prefs.edit()
        if (chiavePubblica == null) editor.remove(verifiedStorageKey(mioId, contattoId))
        else editor.putString(verifiedStorageKey(mioId, contattoId), chiavePubblica)
        editor.apply()
    }
}

/** Sul telefono non c'e una chiave privata per questo account. */
class ChiaviNonConfigurate : IllegalStateException(
    tr(R.string.key_chiavi_cifratura_non_configurate_su_questo)
)
