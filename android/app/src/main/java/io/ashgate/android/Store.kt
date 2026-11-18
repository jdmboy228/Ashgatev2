package io.ashgate.android

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyStore
import java.util.UUID

/**
 * Everything the app saves: profiles (with their keys and passwords), the
 * selected profile and the tunneled apps. It lives only in
 * EncryptedSharedPreferences; the key stays in the Android Keystore.
 *
 * A profile is the JSON object the Go core produced (name, kind, link or
 * host/port/user/pass) plus an "id" added here.
 */
object Store {
    private var cached: SharedPreferences? = null

    /** Set when saved data could not be decrypted and was wiped; the main screen says so once. */
    @Volatile
    private var wiped = false

    @Synchronized
    private fun prefs(ctx: Context): SharedPreferences {
        cached?.let { return it }
        // Twice: the Keystore sometimes fails right after boot.
        val p = tryOpen(ctx) ?: tryOpen(ctx) ?: wipeAndOpen(ctx)
        cached = p
        return p
    }

    private fun tryOpen(ctx: Context): SharedPreferences? = try {
        open(ctx)
    } catch (e: Exception) {
        null
    }

    /**
     * The key in the Keystore is gone or does not fit the file: the data was
     * moved to a new phone (the key never moves), or the Keystore broke.
     * Nothing in the file can be read again, so start over instead of
     * crashing on every launch.
     */
    private fun wipeAndOpen(ctx: Context): SharedPreferences {
        ctx.applicationContext.deleteSharedPreferences(FILE)
        try {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(MASTER_KEY)
        } catch (e: Exception) {
        }
        wiped = true
        return open(ctx)
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
        p.getString("profiles", null)
        p.getStringSet("apps", null)
        return p
    }

    private const val FILE = "ashgate"

    /** The alias MasterKeys.getOrCreate(AES256_GCM_SPEC) uses. */
    private const val MASTER_KEY = "_androidx_security_master_key_"

    /** True once after the saved data had to be wiped. */
    fun takeWiped(ctx: Context): Boolean {
        prefs(ctx)
        if (!wiped) return false
        wiped = false
        return true
    }

    fun profiles(ctx: Context): MutableList<JSONObject> {
        val arr = JSONArray(prefs(ctx).getString("profiles", "[]"))
        return MutableList(arr.length()) { arr.getJSONObject(it) }
    }

    private fun save(ctx: Context, list: List<JSONObject>) {
        prefs(ctx).edit().putString("profiles", JSONArray(list).toString()).apply()
    }

    /** Adds a profile, or replaces the one with the same id. */
    @Synchronized
    fun put(ctx: Context, profile: JSONObject) {
        val list = profiles(ctx)
        if (!profile.has("id")) profile.put("id", UUID.randomUUID().toString())
        val at = list.indexOfFirst { it.getString("id") == profile.getString("id") }
        if (at >= 0) list[at] = profile else list.add(profile)
        save(ctx, list)
        if (selectedId(ctx) == null) select(ctx, profile.getString("id"))
    }

    @Synchronized
    fun delete(ctx: Context, id: String) {
        val list = profiles(ctx).filter { it.getString("id") != id }
        save(ctx, list)
        if (selectedId(ctx) == id) select(ctx, list.firstOrNull()?.getString("id"))
    }

    fun find(ctx: Context, id: String?): JSONObject? =
        profiles(ctx).firstOrNull { it.getString("id") == id }

    fun selectedId(ctx: Context): String? = prefs(ctx).getString("selected", null)

    fun select(ctx: Context, id: String?) {
        prefs(ctx).edit().putString("selected", id).apply()
    }

    fun selected(ctx: Context): JSONObject? = find(ctx, selectedId(ctx))

    /** Package names of the apps that go through the tunnel. */
    fun apps(ctx: Context): Set<String> =
        prefs(ctx).getStringSet("apps", emptySet())!!.toSet()

    fun saveApps(ctx: Context, apps: Set<String>) {
        prefs(ctx).edit().putStringSet("apps", apps).apply()
    }
}
