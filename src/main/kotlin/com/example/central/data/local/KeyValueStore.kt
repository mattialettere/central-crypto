package com.example.central.data.local

// App: shared/src/nonAndroidMain/.../data/local/StorePreferences.kt (excerpt).

/** A key-value store. On iPhone it's the Keychain (reference/ios/KeychainStore.swift). */
interface KeyValueStore {
    fun get(key: String): String?
    fun set(key: String, value: String?)
    fun keys(): Set<String>
}

/** In-memory store, for tests. */
class MemoryKeyValueStore : KeyValueStore {
    private val valori = mutableMapOf<String, String>()
    override fun get(key: String): String? = valori[key]
    override fun set(key: String, value: String?) {
        if (value == null) valori.remove(key) else valori[key] = value
    }
    override fun keys(): Set<String> = valori.keys.toSet()
}
