package io.ashgate.android

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyStore
import java.security.UnrecoverableKeyException
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.SecretKey

/**
 * Everything the app saves: profiles (with their keys and passwords), the
 * selected profile and the tunneled apps. It lives only in
 * EncryptedSharedPreferences; the key stays in the Android Keystore.
 *
 * A profile is the JSON object the Go core produced (name, kind, link or
 * host/port/user/pass) plus an "id" added here.
 */
object Store {
    /** The Keystore is failing right now; the saved data is untouched. */
    class Unavailable : Exception()

    @Volatile
    private var cached: SharedPreferences? = null

    private var cachedProfiles: List<String> = emptyList()
    private var cachedSelected: String? = null
    private var cachedApps: Set<String> = emptySet()

    /** Set when saved data could not be decrypted and was wiped; the main screen says so once. */
    @Volatile
    private var wiped = false

    /** True once the data is open: reading it no longer touches the Keystore. */
    val isOpen: Boolean get() = cached != null

    /** Opens the data if needed; false while the Keystore is failing. Slow the first time. */
    fun usable(ctx: Context): Boolean = try {
        prefs(ctx)
        true
    } catch (e: Unavailable) {
        false
    }

    @Synchronized
    private fun prefs(ctx: Context): SharedPreferences =
        cached ?: openOrWipe(ctx).also { cached = it }

    // Twice, with a short pause: the Keystore sometimes fails right after boot.
    private fun openOrWipe(ctx: Context): SharedPreferences = tryOpen(ctx) ?: run {
        try {
            Thread.sleep(50)
        } catch (_: InterruptedException) {
        }
        tryOpen(ctx)
    } ?: run {
        if (!fileIsLost()) throw Unavailable()
        // The Keystore works now, so a failure from here on is the file's.
        tryOpen(ctx) ?: wipeAndOpen(ctx)
    }

    private fun tryOpen(ctx: Context): SharedPreferences? = try {
        open(ctx)
    } catch (e: Exception) {
        null
    }

    /**
     * Whether the file failed to open for good: the key is gone or dead, or
     * it works and the file still does not open. A Keystore that fails on
     * its own may recover, so then nothing may be deleted.
     */
    private fun fileIsLost(): Boolean {
        try {
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val key = store.getKey(MASTER_KEY, null) as SecretKey? ?: return true
            Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }.doFinal(ByteArray(16))
            return true
        } catch (e: KeyPermanentlyInvalidatedException) {
            return true
        } catch (e: UnrecoverableKeyException) {
            return true
        } catch (e: Exception) {
            return false
        }
    }

    /**
     * The key in the Keystore is gone or does not fit the file: the data was
     * moved to a new phone (the key never moves), or the key broke.
     * Nothing in the file can be read again, so start over instead of
     * failing on every launch.
     */
    private fun wipeAndOpen(ctx: Context): SharedPreferences {
        ctx.applicationContext.deleteSharedPreferences(FILE)
        try {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(MASTER_KEY)
        } catch (e: Exception) {
        }
        wiped = true
        return tryOpen(ctx) ?: throw Unavailable()
    }

    private fun open(ctx: Context): SharedPreferences {
        val p = EncryptedSharedPreferences.create(
            FILE,
            MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
            ctx.applicationContext,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
        // A wrong key can open the file and fail only on the first read.
        // Cache the decrypted values so later UI reads never re-decrypt on the main thread.
        val arr = JSONArray(p.getString("profiles", "[]") ?: "[]")
        cachedProfiles = List(arr.length()) { arr.getJSONObject(it).toString() }
        cachedSelected = p.getString("selected", null)
        cachedApps = p.getStringSet("apps", emptySet())?.toSet() ?: emptySet()
        return p
    }

    private const val FILE = "ashgate"

    /** The alias MasterKeys.getOrCreate(AES256_GCM_SPEC) uses. */
    private const val MASTER_KEY = "_androidx_security_master_key_"

    /** True once after the saved data had to be wiped. */
    @Synchronized
    fun takeWiped(ctx: Context): Boolean {
        prefs(ctx)
        if (!wiped) return false
        wiped = false
        return true
    }

    @Synchronized
    fun profiles(ctx: Context): MutableList<JSONObject> {
        prefs(ctx)
        return MutableList(cachedProfiles.size) { JSONObject(cachedProfiles[it]) }
    }

    private fun save(ctx: Context, list: List<JSONObject>) {
        val p = prefs(ctx)
        cachedProfiles = list.map { it.toString() }
        p.edit().putString("profiles", JSONArray(list).toString()).apply()
    }

    /** Adds a profile, or replaces the one with the same id. */
    @Synchronized
    fun put(ctx: Context, profile: JSONObject) {
        putAll(ctx, listOf(profile))
    }

    /** Adds or replaces several profiles in one encrypted write. */
    @Synchronized
    fun putAll(ctx: Context, incoming: List<JSONObject>) {
        if (incoming.isEmpty()) return
        val list = profiles(ctx)
        for (profile in incoming) {
            if (!profile.has("id")) profile.put("id", UUID.randomUUID().toString())
            val at = list.indexOfFirst { it.getString("id") == profile.getString("id") }
            if (at >= 0) list[at] = profile else list.add(profile)
        }
        save(ctx, list)
        if (selectedId(ctx) == null) select(ctx, incoming.first().getString("id"))
    }

    @Synchronized
    fun delete(ctx: Context, id: String) {
        val list = profiles(ctx).filter { it.getString("id") != id }
        save(ctx, list)
        if (selectedId(ctx) == id) select(ctx, list.firstOrNull()?.getString("id"))
    }

    @Synchronized
    fun find(ctx: Context, id: String?): JSONObject? {
        if (id == null) return null
        return profiles(ctx).firstOrNull { it.getString("id") == id }
    }

    @Synchronized
    fun selectedId(ctx: Context): String? {
        prefs(ctx)
        return cachedSelected
    }

    @Synchronized
    fun select(ctx: Context, id: String?) {
        val p = prefs(ctx)
        cachedSelected = id
        p.edit().putString("selected", id).apply()
    }

    @Synchronized
    fun selected(ctx: Context): JSONObject? = find(ctx, selectedId(ctx))

    /** Package names of the apps that go through the tunnel. */
    @Synchronized
    fun apps(ctx: Context): Set<String> {
        prefs(ctx)
        return cachedApps
    }

    @Synchronized
    fun saveApps(ctx: Context, apps: Set<String>) {
        val p = prefs(ctx)
        val copy = apps.toSet()
        cachedApps = copy
        p.edit().putStringSet("apps", copy).apply()
    }
}
