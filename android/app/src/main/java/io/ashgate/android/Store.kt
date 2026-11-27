package io.ashgate.android

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import org.json.JSONArray
import org.json.JSONObject
import java.security.GeneralSecurityException
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

    // Две попытки с короткой паузой: Android Keystore иногда отвечает отказом сразу после загрузки.
    private fun openOrWipe(ctx: Context): SharedPreferences {
        var lastError: Exception? = null
        tryOpen(ctx) { lastError = it }?.let { return it }
        try {
            Thread.sleep(50)
        } catch (_: InterruptedException) {
        }
        tryOpen(ctx) { lastError = it }?.let { return it }
        if (!fileIsLost(lastError)) throw Unavailable()
        // Ключ либо окончательно потерян, либо рабочий ключ не может расшифровать повреждённый файл.
        return tryOpen(ctx) { lastError = it } ?: wipeAndOpen(ctx)
    }

    private fun tryOpen(ctx: Context, onError: (Exception) -> Unit = {}): SharedPreferences? = try {
        open(ctx)
    } catch (e: Exception) {
        onError(e)
        null
    }

    /**
     * Проверяет, потеряны ли зашифрованные данные безвозвратно:
     * — ключ в Keystore отсутствует или окончательно инвалидирован;
     * — либо ключ исправен, но само расшифровывание файла/keyset упало с крипто-ошибкой.
     * Транзиентные сбои Keystore или ошибки парсинга не приводят к удалению профилей.
     */
    private fun fileIsLost(lastError: Exception?): Boolean {
        try {
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val key = store.getKey(MASTER_KEY, null) as SecretKey? ?: return true
            Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }.doFinal(ByteArray(16))
            return isCryptoFileFailure(lastError)
        } catch (e: KeyPermanentlyInvalidatedException) {
            return true
        } catch (e: UnrecoverableKeyException) {
            return true
        } catch (e: Exception) {
            return false
        }
    }

    /** Ищет в цепочке причин подтверждённую ошибку расшифровки или битого keyset Tink. */
    private fun isCryptoFileFailure(err: Throwable?): Boolean {
        var cur: Throwable? = err
        var depth = 0
        while (cur != null && depth++ < 16) {
            if (cur is GeneralSecurityException || cur is SecurityException) return true
            val name = cur.javaClass.name
            if (name.contains("InvalidProtocolBuffer") || name.contains("AEAD")) return true
            cur = cur.cause
        }
        return false
    }

    /**
     * Ключ в Keystore пропал или не подходит к файлу (например, перенос данных на другой телефон).
     * Прочитать старый файл невозможно, поэтому очищаем его и начинаем с чистого состояния.
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
        // Неверный ключ может открыть файл и упасть только на первом чтении.
        // Кэшируем расшифрованные значения, чтобы последующие чтения UI не дёргали Keystore.
        val rawProfiles = p.getString("profiles", null)
        val selected = p.getString("selected", null)
        val apps = p.getStringSet("apps", emptySet())?.toSet() ?: emptySet()
        // Разбор JSON выполняем отдельно от криптографии: один битый элемент не должен стирать все профили.
        cachedProfiles = parseProfiles(rawProfiles)
        cachedSelected = selected
        cachedApps = apps
        return p
    }

    private fun parseProfiles(raw: String?): List<String> {
        if (raw.isNullOrBlank()) return emptyList()
        val arr = try {
            JSONArray(raw)
        } catch (_: Exception) {
            return emptyList()
        }
        val out = ArrayList<String>(arr.length())
        for (i in 0 until arr.length()) {
            val obj = arr.optJSONObject(i) ?: continue
            if (obj.optString("id").isEmpty()) continue
            out.add(obj.toString())
        }
        return out
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
        // Синхронная запись, чтобы профили не потерялись при резком завершении процесса.
        p.edit().putString("profiles", JSONArray(list).toString()).commit()
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
