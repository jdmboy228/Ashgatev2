package io.ashgate.android

import android.content.Context
import io.ashgate.mobile.Mobile
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

object ProfileImporter {
    data class ImportResult(val count: Int, val firstName: String, val changedIds: Set<String>)

    fun importQr(ctx: Context, raw: String): ImportResult {
        val payload = ProfileQr.parse(raw)
        val found: List<JSONObject> = when (payload) {
            is QrPayload.Invalid -> throw Exception(ctx.getString(R.string.qr_invalid))
            is QrPayload.InsecureSubscription -> throw Exception(ctx.getString(R.string.sub_insecure))
            is QrPayload.VlessLink -> listOf(JSONObject(Mobile.parseLink(payload.link)))
            is QrPayload.Subscription -> {
                val arr = JSONArray(Mobile.parseSubscription(download(ctx, payload.url)))
                List(arr.length()) { arr.getJSONObject(it) }
            }
            is QrPayload.Proxy -> listOf(
                JSONObject(
                    Mobile.parseProxy(
                        payload.kind, payload.name, payload.host, payload.port.toLong(), payload.user, payload.pass,
                    ),
                ),
            )
        }
        return saveProfiles(ctx, found, null)
    }

    fun importForm(
        ctx: Context,
        isVless: Boolean,
        pasted: String,
        proxyKind: String,
        name: String,
        host: String,
        port: Long,
        user: String,
        pass: String,
        editedId: String?,
    ): ImportResult {
        val found: List<JSONObject> = when {
            !isVless -> listOf(
                JSONObject(
                    Mobile.parseProxy(
                        proxyKind, name, host, port, user, pass,
                    ),
                ),
            )
            else -> when (ProfileInput.kind(pasted)) {
                ProfileInput.Kind.INSECURE_SUBSCRIPTION -> throw Exception(ctx.getString(R.string.sub_insecure))
                ProfileInput.Kind.SUBSCRIPTION -> {
                    val arr = JSONArray(Mobile.parseSubscription(download(ctx, pasted)))
                    List(arr.length()) { arr.getJSONObject(it) }
                }
                ProfileInput.Kind.LINK -> listOf(JSONObject(Mobile.parseLink(pasted)))
            }
        }
        return saveProfiles(ctx, found, editedId)
    }

    private fun saveProfiles(ctx: Context, found: List<JSONObject>, editedId: String?): ImportResult {
        if (found.isEmpty()) return ImportResult(0, "", emptySet())
        val saved = Store.profiles(ctx)
            .mapNotNull { p ->
                val k = p.optString("kind").ifEmpty { "vless" }
                ProfileQr.profileKey(k, p.optString("link"), p.optString("host"), p.optInt("port"), p.optString("user"))
                    ?.let { it to p.getString("id") }
            }
            .groupBy({ it.first }, { it.second })
        val incomingKeys = found.map { p ->
            val k = p.optString("kind").ifEmpty { "vless" }
            ProfileQr.profileKey(k, p.optString("link"), p.optString("host"), p.optInt("port"), p.optString("user"))
        }
        val ids = ProfileInput.ids(saved, incomingKeys, editedId)
        found.forEachIndexed { i, p -> ids[i]?.let { p.put("id", it) } }
        Store.putAll(ctx, found)
        if (editedId != null) {
            ProfileInput.duplicateOnEdit(saved, incomingKeys, ids, editedId)?.let { Store.delete(ctx, it) }
        }
        val changedIds = found.map { it.getString("id") }.toSet()
        reconnectIfNeeded(ctx, changedIds)
        return ImportResult(found.size, found.first().optString("name"), changedIds)
    }

    fun reconnectIfNeeded(ctx: Context, changedIds: Set<String>) {
        if (TunnelService.state != TunnelService.State.OFF && Store.selectedId(ctx)?.let { it in changedIds } == true) {
            TunnelService.connect(ctx)
        }
    }

    private fun download(ctx: Context, address: String): ByteArray {
        try {
            val conn = URL(address).openConnection() as HttpURLConnection
            conn.connectTimeout = 15_000
            conn.readTimeout = 15_000
            try {
                if (conn.responseCode != 200) throw Exception()
                return conn.inputStream.use { readAtMost(it, 1 shl 20) }
            } finally {
                conn.disconnect()
            }
        } catch (e: Exception) {
            throw Exception(ctx.getString(R.string.sub_failed))
        }
    }

    private fun readAtMost(input: java.io.InputStream, limit: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (out.size() <= limit) {
            val n = input.read(buf, 0, minOf(buf.size, limit + 1 - out.size()))
            if (n < 0) break
            out.write(buf, 0, n)
        }
        if (out.size() > limit) throw Exception()
        return out.toByteArray()
    }
}
