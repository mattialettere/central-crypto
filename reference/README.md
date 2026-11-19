# Reference platform code

Verbatim copies from the app, for reading. They don't build here: they need
the iOS SDK (with the app's Kotlin `Shared` framework) or the Android SDK.
Comments are in Italian, as in the app.

- `ios/CentralCrypto.swift`: the `CryptoPrimitives` of the iPhone app, with
  CryptoKit (AES-GCM, X25519, SHA-256, HMAC) and CommonCrypto (PBKDF2).
- `ios/KeychainStore.swift`: where the iPhone keeps keys. Keychain items are
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`: not in iCloud backups,
  not transferable to another device.
- `ios/CryptoVectorsTests.swift`, `ios/CentralCryptoTests.swift`: the iOS
  tests run on the simulator against `testvectors/e2e-vectors.json`.
- `android/KeyManager.kt`: where Android keeps keys, in
  `EncryptedSharedPreferences` backed by the Android Keystore. App backup and
  device transfer are disabled in the app's manifest.
- `android/CryptoManager.kt`: the thin Android wrapper over `CryptoCore`.
