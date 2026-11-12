package io.ashgate.android

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import org.json.JSONArray
import org.json.JSONObject
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

    @Synchronized
    private fun prefs(ctx: Context): SharedPreferences {
        cached?.let { return it }
        val p = EncryptedSharedPreferences.create(
            "ashgate",
            MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
            ctx.applicationContext,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
        cached = p
        return p
    }

    fun profiles(ctx: Context): MutableList<JSONObject> {
        val arr = JSONArray(prefs(ctx).getString("profiles", "[]"))
        return MutableList(arr.length()) { arr.getJSONObject(it) }
    }

    private fun save(ctx: Context, list: List<JSONObject>) {
        prefs(ctx).edit().putString("profiles", JSONArray(list).toString()).apply()
    }

    /** Adds a profile, or replaces the one with the same id. */
    fun put(ctx: Context, profile: JSONObject) {
        val list = profiles(ctx)
        if (!profile.has("id")) profile.put("id", UUID.randomUUID().toString())
        val at = list.indexOfFirst { it.getString("id") == profile.getString("id") }
        if (at >= 0) list[at] = profile else list.add(profile)
        save(ctx, list)
        if (selectedId(ctx) == null) select(ctx, profile.getString("id"))
    }

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
