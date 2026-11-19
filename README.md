# Central — end-to-end encryption code

This repository contains the end-to-end encryption code of **Central**, a
private chat and personal-safety app for Android and iPhone
([App Store](https://apps.apple.com/app/id6826663138) ·
[Google Play](https://play.google.com/store/apps/details?id=net.getcentral.central)),
published so that anyone can read it, run its tests and check our claims.

The app itself is not open source. This is the cryptographic core it runs,
copied from the app's private repository with only the changes listed in
[What was changed from the app](#what-was-changed-from-the-app). If you find
a problem, please read [SECURITY.md](SECURITY.md).

> **Please read [Known limitations](#known-limitations) first.** We would
> rather you hear them from us.

## What's inside

| Path | What it is | Runs on |
|---|---|---|
| `src/main/kotlin/.../util/CryptoCore.kt` | Messages (AES-256-GCM), X25519 key agreement, group keys, passphrase backup | Android (Tink) |
| `src/main/kotlin/.../util/MediaCrypto.kt` | Streaming encryption of photos, videos, voice notes and files ("CEMD" format) | Android |
| `src/main/kotlin/.../security/PortableCrypto.kt` | The same protocol on top of a small primitives interface | iPhone (Kotlin Multiplatform) |
| `src/main/kotlin/.../security/MediaCryptoCodec.kt` | The media format for the other platforms | iPhone |
| `src/main/kotlin/.../security/CodiceSicurezza.kt` | Safety numbers (60 digits / QR code) to verify a contact's key, including a pure-Kotlin SHA-512 | Android and iPhone |
| `src/main/kotlin/.../security/JvmPrimitives.kt` | The primitives with `javax.crypto`, used to test the iPhone code on a JVM | tests |
| `reference/ios/CentralCrypto.swift` | The primitives with CryptoKit and CommonCrypto | iPhone |
| `reference/ios/KeychainStore.swift`, `reference/android/KeyManager.kt` | Where keys are stored on each platform (Keychain, EncryptedSharedPreferences) | iPhone, Android |
| `testvectors/` | Shared test vectors and the independent Python generator | everywhere |

`reference/` holds verbatim copies of platform code that can't be built
outside the app (it needs the iOS SDK or the Android SDK). Their comments
are in Italian, as in the app.

## Running the tests

Requirements: JDK 17 or newer, Python 3.10+.

```sh
./gradlew test                                  # 38 tests on the JVM
pip install cryptography
python3 testvectors/genera_vettori.py --check   # vectors recomputed independently
```

The JVM tests cover the Android code (with Tink, as in the app) and the
code the iPhone runs (with `javax.crypto` primitives). The values in
`testvectors/e2e-vectors.json` are computed by `testvectors/genera_vettori.py`
with the Python `cryptography` library (OpenSSL), a fourth implementation
that shares no code with Tink, `javax.crypto` or CryptoKit. In the app's own
CI the same vectors are also checked with CryptoKit on the iOS simulator
(`reference/ios/CryptoVectorsTests.swift`).

The vectors pin, byte for byte: X25519 (RFC 7748) and the derived chat key,
four messages, a group-key envelope, the PBKDF2-derived backup key and the
encrypted backup, two encrypted media files (one larger than the 64 KB
streaming buffer) and three safety-number cases. The tests also check that
tampered data (a flipped tag bit, a modified media header, a wrong backup
passphrase) is rejected rather than decrypted.

## The protocol in short

Full description: [PROTOCOL.md](PROTOCOL.md).

- **Identity:** each user has one X25519 key pair per account, generated on
  the device. The private key never leaves the device in clear.
- **One-to-one chats:** key = SHA-256(X25519(my private, their public)).
  Messages: AES-256-GCM, random 96-bit IV, 128-bit tag.
- **Groups:** a random AES-256 group key, versioned and rotated when members
  leave, sent to each member encrypted with the pairwise key between the
  admin and that member.
- **Media:** a per-file key derived with HKDF-SHA256 from the conversation
  key and a random salt; AES-256-GCM with the whole header as associated data.
- **Backup (optional):** the private key encrypted with a key derived from the
  user's passphrase (PBKDF2-HMAC-SHA256, 210,000 iterations), stored on the
  server so the user can restore it on a new phone.
- **Safety numbers:** 60 digits (or a QR code) per one-to-one chat, computed
  as in Signal's numeric fingerprint v0, to detect a replaced public key.

## Known limitations

These are real and known. Some are planned for a protocol v2 (below).

1. **No forward secrecy.** The one-to-one key is derived from long-term
   X25519 keys and doesn't change. If a private key is ever stolen, past
   messages encrypted to it can be read too. Signal and WhatsApp avoid this
   with a ratchet.
2. **Key verification is optional.** Safety numbers exist, but most people
   won't compare them. Until a contact is verified, someone who controls the
   server or steals a user's session could publish a different public key
   for that user. The app shows a "security keys updated" notice when a key
   changes, a verified contact whose key changes is flagged in the chat, and
   changing one's own key requires a recent login.
3. **Messages aren't bound to their context.** Message encryption uses no
   associated data, so a message isn't cryptographically tied to its chat,
   sender or position. The server could replay or reorder ciphertexts it
   already has. (Media files do authenticate their header.)
4. **The key backup is only as strong as the passphrase.** It is stored on
   the server; PBKDF2 slows down guessing but a weak passphrase can still be
   brute-forced offline by whoever holds the backup. New passphrases must be
   at least 12 characters. The backup is optional.
5. **Not everything is end-to-end encrypted.** Chat messages, media, group
   keys, SOS alerts (location, battery, video), safe-trip positions and boards
   are. **Metadata is not**: the server knows who talks to whom and when, and
   sizes. **Safe zones are not**: zone definitions and the enter/exit events,
   with coordinates, are stored on the server so trusted contacts and
   organizations can see them in the web dashboard.
6. **You have to trust that the app runs this code.** There are no
   reproducible builds yet, so nobody can prove the published app is built
   from exactly these files. We keep them in sync with the app on every
   change to the encryption.
7. **Not included here:** the guardian web dashboard has its own browser
   implementation (WebCrypto) of the same format, which is not in this
   repository yet. Server code is not included; the server never receives
   private keys or plaintext of end-to-end encrypted content.
8. **No independent audit yet.** This code hasn't been reviewed by a security
   firm. Publishing it is a first step; a professional audit is planned when
   the project can afford one.

## Plan for protocol v2

Not scheduled yet; listed in order of expected value.

- **Associated data on messages:** bind each ciphertext to chat id, sender id
  and message id.
- **HKDF instead of a bare SHA-256** to derive the one-to-one key, with
  context labels.
- **Forward secrecy:** move one-to-one chats to a double ratchet (most likely
  by adopting an existing, audited library rather than writing our own).
- **Stronger backup KDF:** Argon2id with memory hardness, with a migration
  path for existing backups.
- **Reproducible builds** of the Android app.
- Publish the web dashboard implementation here as well.

## What was changed from the app

The app keeps these files under the same package names
(`com.example.central.*`, a historical name). Compared with the app:

- comments translated from Italian into English;
- translated UI strings (`tr(...)`) replaced by English constants, and log
  calls removed, so the code builds without the app;
- `KeyValueStore` / `MemoryKeyValueStore` extracted from a larger file;
- `JvmPrimitives` moved from the app's tests into `src/main`;
- the plain-JVM `tink` artifact instead of `tink-android` (same API);
- tests: copied as they are in the app (test names are in Italian), minus one
  test of an Android-only wrapper (`CryptoManager`, see `reference/android`).

A small glossary for the Italian identifiers: *cifra* = encrypt, *decifra* =
decrypt, *chiave* = key, *privata/pubblica* = private/public, *segreto
condiviso* = shared secret, *busta* = envelope, *gruppo* = group, *impronta* =
fingerprint, *codice di sicurezza* = safety number, *verificato* = verified,
*vettori* = vectors.

## License

[Apache License 2.0](LICENSE). Copyright 2026 the Central developers (getcentral.net).
