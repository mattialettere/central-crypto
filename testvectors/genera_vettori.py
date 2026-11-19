#!/usr/bin/env python3
"""
Genera testvectors/e2e-vectors.json: i vettori di prova della cifratura E2E
di Central, uguali per Android (CryptoCore, MediaCrypto), per il codice
comune (PortableContentCrypto, PortableKeyVault, MediaCryptoCodec) e per
iPhone (CentralCrypto, CryptoKit), piu' il codice di sicurezza (CodiceSicurezza,
Kotlin comune: SHA-512 iterato come il "numeric fingerprint" di Signal).

I valori attesi li calcola questo script con la libreria Python
"cryptography" (OpenSSL), cioe' un'implementazione diversa da Tink,
javax.crypto e CryptoKit. Se tutte e tre le piattaforme ritrovano gli stessi
byte, il protocollo e' lo stesso ovunque; se una libreria cambia un valore
di default (lunghezza dell'IV o del tag, codifica della passphrase, ordine
dei byte di X25519...), un test fallisce prima che un utente smetta di
leggere i messaggi.

Uso:
    pip install cryptography
    python3 testvectors/genera_vettori.py           # riscrive il JSON
    python3 testvectors/genera_vettori.py --check   # esce con 1 se il JSON non torna

Il JSON va rigenerato solo se il protocollo cambia di proposito: in quel
caso cambiano anche i test, e i messaggi vecchi vanno ancora letti.
"""
import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FILE = Path(__file__).resolve().parent / "e2e-vectors.json"

# Costanti del protocollo (CryptoCore.kt, PortableCrypto.kt, MediaCrypto.kt).
PBKDF2_ITERATIONS = 210_000
MEDIA_MAGIC = b"CEMD"
MEDIA_VERSION = 1
MEDIA_HKDF_INFO = b"central-media-v1"
MEDIA_KEY_ID_INFO = b"central-media-key-id"
SAFETY_ITERATIONS = 5_200
SAFETY_QR_PREFIX = "CENTRAL-SN1:"


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def seq(n: int, start: int = 0) -> bytes:
    """Byte start, start+1, ... (mod 256): valori fissi facili da riconoscere."""
    return bytes((start + i) % 256 for i in range(n))


def pattern(n: int) -> bytes:
    """Contenuto lungo e deterministico per i media: byte i = (i * 31 + 7) % 251."""
    return bytes((i * 31 + 7) % 251 for i in range(n))


def gcm(key: bytes, iv: bytes, plain: bytes, aad: bytes | None = None) -> bytes:
    # ciphertext seguito dal tag da 16 byte, come Tink/javax/CryptoKit nel codice.
    return AESGCM(key).encrypt(iv, plain, aad)


def x25519_pub(priv: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def x25519_shared(priv: bytes, pub: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(priv).exchange(X25519PublicKey.from_public_bytes(pub))


def media_blob(base_key: bytes, salt: bytes, iv: bytes, plain: bytes) -> tuple[bytes, str]:
    key_id = hashlib.sha256(MEDIA_KEY_ID_INFO + base_key).digest()[:4]
    header = MEDIA_MAGIC + bytes([MEDIA_VERSION]) + key_id + salt + iv
    prk = hmac.new(salt, base_key, hashlib.sha256).digest()
    file_key = hmac.new(prk, MEDIA_HKDF_INFO + b"\x01", hashlib.sha256).digest()[:32]
    return header + gcm(file_key, iv, plain, header), key_id.hex()


def impronta_sicurezza(pub: bytes, user_id: str) -> str:
    """Le 30 cifre di una persona (CodiceSicurezza.impronta, come Signal v0)."""
    h = b"\x00\x00" + pub + user_id.encode("utf-8")
    for _ in range(SAFETY_ITERATIONS):
        h = hashlib.sha512(h + pub).digest()
    return "".join(f"{int.from_bytes(h[i:i + 5], 'big') % 100_000:05d}" for i in range(0, 30, 5))


def codice_sicurezza(id_a: str, pub_a: bytes, id_b: str, pub_b: bytes) -> str:
    a, b = impronta_sicurezza(pub_a, id_a), impronta_sicurezza(pub_b, id_b)
    return a + b if a <= b else b + a


def genera() -> dict:
    # ── X25519: vettori ufficiali di RFC 7748, sezione 6.1 ──────────────
    alice_priv = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bob_priv = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    alice_pub, bob_pub = x25519_pub(alice_priv), x25519_pub(bob_priv)
    raw = x25519_shared(alice_priv, bob_pub)
    assert raw == x25519_shared(bob_priv, alice_pub)
    assert alice_pub.hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    assert raw.hex() == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    # La chiave di una chat a due: SHA-256 del segreto X25519 grezzo.
    chat_key = hashlib.sha256(raw).digest()

    # ── Messaggi: AES-256-GCM, IV da 12 byte in un campo a parte ───────
    messaggi = []
    def msg(nome, key, iv, testo):
        messaggi.append({
            "name": nome,
            "key_b64": b64(key),
            "iv_b64": b64(iv),
            "plaintext": testo,
            "ciphertext_b64": b64(gcm(key, iv, testo.encode("utf-8"))),
        })
    k = seq(32)
    msg("accenti_ed_emoji", k, seq(12), "Central è sicura 😀")
    msg("vuoto", k, seq(12, 100), "")
    msg("lungo_piu_blocchi", k, seq(12, 200),
        "Sono arrivata a casa. " * 20 + "Ci vediamo domani alle 18:30 — 🏠✅ ñ ß ü 中文")
    msg("chat_a_due_alice_bob", chat_key, seq(12, 7), "Ciao Bob, sono Alice 👋")

    # ── Busta di una chiave di gruppo: la chiave AES-256 del gruppo cifrata,
    # come byte grezzi, con la chiave della chat a due fra admin e membro.
    group_key = seq(32, 0xA0)
    env_iv = seq(12, 0x40)
    busta = {
        "pairwise_key_b64": b64(chat_key),
        "group_key_b64": b64(group_key),
        "iv_b64": b64(env_iv),
        "ciphertext_b64": b64(gcm(chat_key, env_iv, group_key)),
    }

    # ── Backup della chiave privata: PBKDF2-HMAC-SHA256 (passphrase UTF-8,
    # 210.000 iterazioni, 32 byte) e AES-256-GCM sulla privata grezza.
    passphrase = "passphrase giusta è lunga 🔑"
    salt, iv = seq(16), seq(12, 0x30)
    kdf = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, PBKDF2_ITERATIONS, 32)
    backup = {
        "passphrase": passphrase,
        "iterations": PBKDF2_ITERATIONS,
        "salt_b64": b64(salt),
        "iv_b64": b64(iv),
        "derived_key_hex": kdf.hex(),
        "private_key_b64": b64(alice_priv),
        "ciphertext_b64": b64(gcm(kdf, iv, alice_priv)),
        "wrong_passphrase": "passphrase sbagliata",
    }

    # ── Media: "CEMD" | versione | keyId | salt | iv | ciphertext+tag ────
    media = []
    def med(nome, base_key, salt, iv, plain, completo):
        blob, key_id = media_blob(base_key, salt, iv, plain)
        v = {
            "name": nome,
            "base_key_b64": b64(base_key),
            "salt_b64": b64(salt),
            "iv_b64": b64(iv),
            "key_id_hex": key_id,
            "header_hex": blob[:37].hex(),
            "blob_length": len(blob),
            "blob_sha256_hex": hashlib.sha256(blob).hexdigest(),
        }
        if completo:
            v["plaintext_b64"] = b64(plain)
        else:
            # Il contenuto in chiaro lo ricostruisce il test: byte i = (i * 31 + 7) % 251.
            v["plaintext_pattern"] = {"length": len(plain), "formula": "(i * 31 + 7) % 251"}
        v["blob_b64"] = b64(blob)
        media.append(v)
    med("foto_piccola", chat_key, seq(16, 0x10), seq(12, 0x20), "una foto 📷".encode("utf-8"), True)
    # Piu' grande del buffer da 64 KB (65.536 byte) di MediaCrypto: la cifratura a flusso
    # di Android deve dare gli stessi byte di quella in memoria di iOS.
    med("video_oltre_64kb", seq(32, 0x55), seq(16, 0x66), seq(12, 0x77), pattern(70_000), False)

    # ── Codice di sicurezza (verifica a voce o con il QR, come WhatsApp) ──
    # Id utente come li manda il server; il terzo caso e' la chiave di Bob
    # sostituita (attacco o reinstallazione): il codice deve cambiare.
    mallory_pub = x25519_pub(seq(32, 0x99))
    sicurezza = []
    def sn(nome, id_a, pub_a, id_b, pub_b):
        codice = codice_sicurezza(id_a, pub_a, id_b, pub_b)
        sicurezza.append({
            "name": nome,
            "user_a": id_a,
            "public_a_b64": b64(pub_a),
            "user_b": id_b,
            "public_b_b64": b64(pub_b),
            "fingerprint_a": impronta_sicurezza(pub_a, id_a),
            "fingerprint_b": impronta_sicurezza(pub_b, id_b),
            "safety_number": codice,
            "qr": SAFETY_QR_PREFIX + codice,
        })
    sn("alice_bob_id_brevi", "a", alice_pub, "b", bob_pub)
    sn("alice_bob_uuid", "3f2c9a1e-7b4d-4e8a-9c21-5d6f0a1b2c3d", alice_pub,
       "b81e4f20-0c3a-4d59-8e7f-112233445566", bob_pub)
    sn("chiave_di_bob_sostituita", "3f2c9a1e-7b4d-4e8a-9c21-5d6f0a1b2c3d", alice_pub,
       "b81e4f20-0c3a-4d59-8e7f-112233445566", mallory_pub)

    return {
        "description": "Vettori di prova E2E di Central, generati da testvectors/genera_vettori.py "
                       "con la libreria Python cryptography. Non modificare a mano.",
        "version": 1,
        "x25519": {
            "source": "RFC 7748 6.1",
            "alice_private_hex": alice_priv.hex(),
            "alice_public_b64": b64(alice_pub),
            "bob_private_hex": bob_priv.hex(),
            "bob_public_b64": b64(bob_pub),
            "shared_raw_hex": raw.hex(),
            "chat_key_b64": b64(chat_key),
        },
        "messages": messaggi,
        "group_key_envelope": busta,
        "key_backup": backup,
        "media": media,
        "safety_numbers": {
            "iterations": SAFETY_ITERATIONS,
            "qr_prefix": SAFETY_QR_PREFIX,
            "cases": sicurezza,
        },
    }


def main() -> int:
    testo = json.dumps(genera(), ensure_ascii=False, indent=2) + "\n"
    if "--check" in sys.argv:
        if not FILE.exists() or FILE.read_text(encoding="utf-8") != testo:
            print(f"{FILE} non corrisponde ai valori calcolati: rigeneralo o controlla le modifiche.")
            return 1
        print("Vettori E2E: OK")
        return 0
    FILE.write_text(testo, encoding="utf-8")
    print(f"Scritto {FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
