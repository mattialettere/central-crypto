package com.example.central.util

/**
 * Result of encrypting the private-key backup: the only thing uploaded to the
 * server. The server stores ONLY these three values. It never has the
 * passphrase or the private key in clear, so it cannot decrypt messages.
 */
data class KeyBackupPayload(
    val ciphertextBase64: String,
    val ivBase64: String,
    val saltBase64: String,
)
