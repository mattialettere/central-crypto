import Foundation
import Security
import Shared

/// Un archivio chiave-valore nel Portachiavi (KeyValueStore in
/// shared/src/nonAndroidMain/.../data/local/StorePreferences.kt).
///
/// Ci vanno i token di sessione e le chiavi di cifratura: come su Android
/// stanno in DataStore e in EncryptedSharedPreferences, qui in due servizi
/// separati. Accessibili dopo il primo sblocco e solo su questo iPhone: non
/// finiscono nei backup di iCloud, come le chiavi Android non escono dal
/// telefono.
final class KeychainStore: KeyValueStore {
    private let service: String

    init(service: String) {
        self.service = service
    }

    private func base(_ key: String? = nil) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        if let key { q[kSecAttrAccount as String] = key }
        return q
    }

    func get(key: String) -> String? {
        var q = base(key)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var risultato: AnyObject?
        let esito = SecItemCopyMatching(q as CFDictionary, &risultato)
        if esito == errSecInteractionNotAllowed {
            // iPhone riacceso e non ancora sbloccato: la voce c'e' ma non si legge.
            NSLog("KeychainStore: %@ non leggibile prima del primo sblocco", key)
            return nil
        }
        guard esito == errSecSuccess, let dati = risultato as? Data else { return nil }
        return String(data: dati, encoding: .utf8)
    }

    /// Prima aggiorna, poi (se manca) aggiunge. Prima la voce veniva
    /// cancellata e riscritta: se la scrittura falliva (iPhone appena
    /// riacceso e bloccato) il token era perso e si tornava al login.
    func set(key: String, value: String?) {
        guard Self.datiDisponibili() else {
            NSLog("KeychainStore: scrittura di %@ rimandata, iPhone non ancora sbloccato", key)
            return
        }
        guard let value else {
            SecItemDelete(base(key) as CFDictionary)
            return
        }
        let dati = Data(value.utf8)
        let aggiorna: [String: Any] = [
            kSecValueData as String: dati,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        var esito = SecItemUpdate(base(key) as CFDictionary, aggiorna as CFDictionary)
        if esito == errSecItemNotFound {
            var q = base(key)
            q[kSecValueData as String] = dati
            q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            esito = SecItemAdd(q as CFDictionary, nil)
        }
        if esito != errSecSuccess {
            NSLog("KeychainStore: scrittura di %@ fallita (%d)", key, esito)
        }
    }

    func keys() -> Set<String> {
        var q = base()
        q[kSecReturnAttributes as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitAll
        var risultato: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &risultato) == errSecSuccess,
              let voci = risultato as? [[String: Any]] else { return [] }
        return Set(voci.compactMap { $0[kSecAttrAccount as String] as? String })
    }
}

// MARK: - Dati protetti dopo il riavvio

extension KeychainStore {

    private static let sonda = "net.getcentral.central.sonda"

    /// Vero dal primo sblocco dopo l'accensione: una voce di prova, con la
    /// stessa protezione dei token, si legge solo da allora. Se manca (primo
    /// avvio in assoluto) i dati sono leggibili e la si crea.
    static func datiDisponibili() -> Bool {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: sonda,
            kSecAttrAccount as String: "sonda",
        ]
        var q = base
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var risultato: AnyObject?
        switch SecItemCopyMatching(q as CFDictionary, &risultato) {
        case errSecSuccess:
            return true
        case errSecInteractionNotAllowed:
            return false
        case errSecItemNotFound:
            var nuova = base
            nuova[kSecValueData as String] = Data("ok".utf8)
            nuova[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            return SecItemAdd(nuova as CFDictionary, nil) != errSecInteractionNotAllowed
        default:
            return true
        }
    }
}

/// La sonda per Kotlin (IosDatiProtetti).
final class SondaPortachiavi: NSObject, SondaDatiProtetti {
    func disponibili() -> Bool { KeychainStore.datiDisponibili() }
}
