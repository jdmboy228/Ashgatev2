package io.ashgate.android

import android.app.Activity
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.RadioGroup
import android.widget.TextView
import io.ashgate.android.TunnelService.State
import io.ashgate.mobile.Mobile
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

/**
 * Adds or edits a profile. VLESS takes a vless:// link or a 3x-ui
 * subscription address (every XHTTP server of it becomes a profile); SOCKS5
 * and HTTP take the form. The Go core checks all of it.
 */
class ProfileActivity : Activity() {
    private lateinit var kind: RadioGroup
    private lateinit var link: EditText
    private lateinit var proxy: View
    private lateinit var error: TextView
    private lateinit var save: Button
    private lateinit var delete: Button
    private var id: String? = null

    @Volatile
    private var closed = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Reopened by the system with the Keystore failing: back to the main screen's message.
        if (!Store.usable(this)) return finish()
        // The form shows the link and the password: not in Recents or screenshots.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(R.layout.profile)
        kind = findViewById(R.id.kind)
        link = findViewById(R.id.link)
        proxy = findViewById(R.id.proxy)
        error = findViewById(R.id.error)
        save = findViewById(R.id.save)
        delete = findViewById(R.id.delete)

        id = intent.getStringExtra("id")
        val old = Store.find(this, id)
        kind.setOnCheckedChangeListener { _, checked ->
            link.visibility = if (checked == R.id.kind_vless) View.VISIBLE else View.GONE
            proxy.visibility = if (checked == R.id.kind_vless) View.GONE else View.VISIBLE
            findViewById<View>(R.id.proxy_note).visibility = proxy.visibility
        }
        kind.check(
            when (old?.optString("kind")) {
                "socks5" -> R.id.kind_socks5
                "http" -> R.id.kind_http
                else -> R.id.kind_vless
            },
        )
        if (old != null) {
            link.setText(old.optString("link"))
            if (old.optString("kind") != "vless") {
                field(R.id.name).setText(old.optString("name"))
                field(R.id.host).setText(old.optString("host"))
                field(R.id.port).setText(old.optInt("port").toString())
                field(R.id.user).setText(old.optString("user"))
                field(R.id.pass).setText(old.optString("pass"))
            }
            delete.apply {
                visibility = View.VISIBLE
                setOnClickListener {
                    closed = true
                    val wasSelected = Store.selectedId(this@ProfileActivity) == this@ProfileActivity.id
                    Store.delete(this@ProfileActivity, this@ProfileActivity.id!!)
                    if (wasSelected) reconnect()
                    finish()
                }
            }
        }
        save.setOnClickListener { save() }
    }

    override fun onDestroy() {
        closed = true
        super.onDestroy()
    }

    private fun field(id: Int): EditText = findViewById(id)

    private fun text(id: Int): String = field(id).text.toString()

    private fun save() {
        error.visibility = View.GONE
        save.isEnabled = false
        delete.isEnabled = false
        val vless = kind.checkedRadioButtonId == R.id.kind_vless
        val pasted = link.text.toString().trim()
        val proxyKind = if (kind.checkedRadioButtonId == R.id.kind_http) "http" else "socks5"
        val form = listOf(R.id.name, R.id.host, R.id.port, R.id.user, R.id.pass).map(::text)
        // The subscription is downloaded here, so off the main thread.
        thread {
            var changed = emptySet<String>()
            val failure = try {
                val found: List<JSONObject> = when {
                    !vless -> listOf(
                        JSONObject(
                            Mobile.parseProxy(
                                proxyKind, form[0], form[1], form[2].trim().toLongOrNull() ?: 0, form[3], form[4],
                            ),
                        ),
                    )
                    else -> when (ProfileInput.kind(pasted)) {
                        ProfileInput.Kind.INSECURE_SUBSCRIPTION -> throw Exception(getString(R.string.sub_insecure))
                        ProfileInput.Kind.SUBSCRIPTION -> {
                            val arr = JSONArray(Mobile.parseSubscription(download(pasted)))
                            List(arr.length()) { arr.getJSONObject(it) }
                        }
                        ProfileInput.Kind.LINK -> listOf(JSONObject(Mobile.parseLink(pasted)))
                    }
                }
                if (closed || isFinishing || isDestroyed) return@thread
                // An edited profile keeps its place. A server that is already
                // saved (the same subscription imported again) is replaced
                // instead of added a second time.
                val saved = Store.profiles(this)
                    .mapNotNull { p -> ProfileInput.serverKey(p.optString("link"))?.let { it to p.getString("id") } }
                    .groupBy({ it.first }, { it.second })
                val ids = ProfileInput.ids(saved, found.map { ProfileInput.serverKey(it.optString("link")) }, id)
                found.forEachIndexed { i, p -> ids[i]?.let { p.put("id", it) } }
                found.forEach { Store.put(this, it) }
                changed = found.map { it.getString("id") }.toSet()
                null
            } catch (e: Exception) {
                e.message ?: e.javaClass.simpleName
            }
            runOnUiThread {
                if (closed || isFinishing || isDestroyed) return@runOnUiThread
                if (failure == null) {
                    // The selected profile changed (edited, or replaced by a re-import).
                    if (Store.selectedId(this)?.let { it in changed } == true) reconnect()
                    finish()
                } else {
                    save.isEnabled = true
                    delete.isEnabled = true
                    error.text = failure
                    error.visibility = View.VISIBLE
                }
            }
        }
    }

    /** A running tunnel picks up the changed profile, or stops when none are left. */
    private fun reconnect() {
        if (TunnelService.state == State.OFF) return
        if (Store.selectedId(this) == null) TunnelService.disconnect(this) else TunnelService.connect(this)
    }

    /** Errors never quote the address: it holds the subscription's token. */
    private fun download(address: String): ByteArray {
        try {
            val conn = URL(address).openConnection() as HttpURLConnection
            conn.connectTimeout = 15_000
            conn.readTimeout = 15_000
            try {
                if (conn.responseCode != 200) throw Exception()
                return conn.inputStream.use { it.readAtMost(1 shl 20) }
            } finally {
                conn.disconnect()
            }
        } catch (e: Exception) {
            throw Exception(getString(R.string.sub_failed))
        }
    }

    /** Reads at most [limit] bytes; fails if the stream is longer so a subscription is never cut in half. */
    private fun java.io.InputStream.readAtMost(limit: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (out.size() <= limit) {
            val n = read(buf, 0, minOf(buf.size, limit + 1 - out.size()))
            if (n < 0) break
            out.write(buf, 0, n)
        }
        if (out.size() > limit) throw Exception()
        return out.toByteArray()
    }
}
