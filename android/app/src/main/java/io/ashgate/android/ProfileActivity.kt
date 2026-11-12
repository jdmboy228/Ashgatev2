package io.ashgate.android

import android.app.Activity
import android.os.Bundle
import android.view.View
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
    private var id: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.profile)
        kind = findViewById(R.id.kind)
        link = findViewById(R.id.link)
        proxy = findViewById(R.id.proxy)
        error = findViewById(R.id.error)
        save = findViewById(R.id.save)

        id = intent.getStringExtra("id")
        val old = Store.find(this, id)
        kind.setOnCheckedChangeListener { _, checked ->
            link.visibility = if (checked == R.id.kind_vless) View.VISIBLE else View.GONE
            proxy.visibility = if (checked == R.id.kind_vless) View.GONE else View.VISIBLE
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
            findViewById<Button>(R.id.delete).apply {
                visibility = View.VISIBLE
                setOnClickListener {
                    val wasSelected = Store.selectedId(this@ProfileActivity) == id
                    Store.delete(this@ProfileActivity, id!!)
                    if (wasSelected) reconnect()
                    finish()
                }
            }
        }
        save.setOnClickListener { save() }
    }

    private fun field(id: Int): EditText = findViewById(id)

    private fun text(id: Int): String = field(id).text.toString()

    private fun save() {
        error.visibility = View.GONE
        save.isEnabled = false
        val vless = kind.checkedRadioButtonId == R.id.kind_vless
        val pasted = link.text.toString().trim()
        val proxyKind = if (kind.checkedRadioButtonId == R.id.kind_http) "http" else "socks5"
        val form = listOf(R.id.name, R.id.host, R.id.port, R.id.user, R.id.pass).map(::text)
        // The subscription is downloaded here, so off the main thread.
        thread {
            val failure = try {
                val found: List<JSONObject> = when {
                    !vless -> listOf(
                        JSONObject(
                            Mobile.parseProxy(
                                proxyKind, form[0], form[1], form[2].trim().toLongOrNull() ?: 0, form[3], form[4],
                            ),
                        ),
                    )
                    pasted.startsWith("http://", true) || pasted.startsWith("https://", true) -> {
                        val arr = JSONArray(Mobile.parseSubscription(download(pasted)))
                        List(arr.length()) { arr.getJSONObject(it) }
                    }
                    else -> listOf(JSONObject(Mobile.parseLink(pasted)))
                }
                // An edited profile keeps its place; a subscription's other servers are added.
                id?.let { found[0].put("id", it) }
                found.forEach { Store.put(this, it) }
                null
            } catch (e: Exception) {
                e.message ?: e.javaClass.simpleName
            }
            runOnUiThread {
                if (failure == null) {
                    if (id != null && id == Store.selectedId(this)) reconnect()
                    finish()
                } else {
                    save.isEnabled = true
                    error.text = failure
                    error.visibility = View.VISIBLE
                }
            }
        }
    }

    /** A running tunnel picks up the changed profile. */
    private fun reconnect() {
        if (TunnelService.state != State.OFF) TunnelService.connect(this)
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

    /** Reads at most [limit] bytes. */
    private fun java.io.InputStream.readAtMost(limit: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (out.size() < limit) {
            val n = read(buf, 0, minOf(buf.size, limit - out.size()))
            if (n < 0) break
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }
}
