# Central E2E protocol (version 1)

This describes what the code in this repository does. Byte-exact examples
for every step are in `testvectors/e2e-vectors.json`.

Notation: `||` is concatenation; Base64 is standard RFC 4648 with padding
(decoders also accept line breaks); text is UTF-8.

## 1. Identity keys

- On first use, each device generates an X25519 private key (32 random bytes)
  for the account and stores it locally: Android Keystore-backed
  EncryptedSharedPreferences, iOS Keychain (this device only, not in iCloud
  backups).
- The public key (32 bytes, Base64) is uploaded to the server, which hands
  it to the user's contacts.
- Replacing one's public key on the server requires a recent login, and the
  server then posts a "security keys updated" notice in that user's chats.

## 2. One-to-one chats

```
chat_key = SHA-256( X25519(my_private, their_public) )          // 32 bytes
```

Both sides compute the same `chat_key`. Each message:

```
iv         = 12 random bytes
ciphertext = AES-256-GCM(key = chat_key, iv, plaintext UTF-8, no AAD)   // ct || 16-byte tag
sent       = { ciphertext: Base64(ct || tag), iv: Base64(iv) }
```

Decryption failures are never shown as text: the app shows a placeholder.

## 3. Groups

- The admin creates a random 32-byte group key with a version number.
- For each member, the admin sends an *envelope*: the group key encrypted
  with AES-256-GCM under the pairwise `chat_key` between admin and member
  (same format as a message, on raw bytes).
- Group messages are encrypted with the group key of the current version.
- When someone is removed or leaves, the next admin who opens the group
  publishes a new version of the key to the remaining members. Old versions
  are kept locally to read old messages.

## 4. Media (photos, videos, voice notes, files)

```
salt     = 16 random bytes,  iv = 12 random bytes
key_id   = SHA-256("central-media-key-id" || base_key)[0..4]
file_key = HKDF-SHA256(salt, IKM = base_key, info = "central-media-v1", L = 32)
header   = "CEMD" || 0x01 || key_id || salt || iv                 // 37 bytes
blob     = header || AES-256-GCM(file_key, iv, file, AAD = header)
```

`base_key` is the conversation key (chat or group key). For SOS videos, which
go to several emergency contacts, it's a random key carried inside the SOS
message, which is end-to-end encrypted separately for each contact. Only
`blob` is uploaded.

## 5. Optional key backup

So a user can restore the private key on a new phone:

```
salt   = 16 random bytes,  iv = 12 random bytes
k      = PBKDF2-HMAC-SHA256(passphrase UTF-8, salt, 210 000 iterations, 32 bytes)
backup = { ciphertext: Base64(AES-256-GCM(k, iv, private_key)), iv, salt }
```

`backup` is stored on the server. Restoring with a wrong passphrase fails on
the GCM tag. New passphrases need at least 12 characters. Downloading the
backup requires a recent login.

## 6. Safety numbers

For a one-to-one chat between A and B (Signal "numeric fingerprint" v0, with
the raw 32-byte X25519 key):

```
for each person P with public key K and user id U:
    h = 0x0000 || K || U
    repeat 5200 times: h = SHA-512(h || K)
    fp(P) = for i in 0..5: (big-endian int of h[5i .. 5i+5]) mod 100000, as 5 digits   // 30 digits
safety_number = min(fp(A), fp(B)) || max(fp(A), fp(B))                                   // 60 digits
QR code      = "CENTRAL-SN1:" || safety_number
```

Users compare the 60 digits out loud or scan each other's QR code. The app
remembers *which* key of the contact was verified; if it changes, the chat
shows a warning until the user verifies again.

## 7. What the server sees

| Data | Server sees |
|---|---|
| Chat and group messages, group keys | ciphertext only |
| Photos, videos, voice notes, files | encrypted blobs only |
| SOS alerts (location, battery, video key) | ciphertext only, encrypted separately for each emergency contact |
| Safe-trip positions and destination, board contents | ciphertext only |
| Private keys | never; only the optional passphrase-encrypted backup |
| Public keys | yes |
| Metadata: who talks to whom, when, message and file sizes, group membership | yes |
| Safe zones: zone definitions and enter/exit events with coordinates | **yes, in clear**, shown to trusted contacts and organizations in the web dashboard |
| Account data (email, name, contacts list) | yes |

## 8. Known weaknesses

See [README.md](README.md#known-limitations): no forward secrecy, no
associated data on messages, optional key verification, backup strength
depending on the passphrase, metadata and safe zones visible to the server,
no reproducible builds.
