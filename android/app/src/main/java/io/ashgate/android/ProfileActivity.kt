package io.ashgate.android

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.RadioGroup
import android.widget.TextView
import io.ashgate.android.TunnelService.State
import kotlin.concurrent.thread

/**
 * Adds or edits a profile. VLESS takes a vless:// link or a 3x-ui
 * subscription address (every XHTTP server of it becomes a profile); SOCKS5
 * and HTTP take the form. The Go core checks all of it.
 */
class ProfileActivity : Activity() {
    companion object {
        private const val REQ_QR_SCAN = 101
    }

    private lateinit var kind: RadioGroup
    private lateinit var link: EditText
    private lateinit var proxy: View
    private lateinit var error: TextView
    private lateinit var save: Button
    private lateinit var scanQr: Button
    private lateinit var showQr: Button
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
        scanQr = findViewById(R.id.scan_qr)
        showQr = findViewById(R.id.show_qr)
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
            showQr.apply {
                visibility = View.VISIBLE
                onClick {
                    startActivity(
                        Intent(this@ProfileActivity, ProfileQrActivity::class.java)
                            .putExtra(ProfileQrActivity.EXTRA_PROFILE_ID, id),
                    )
                }
            }
            delete.apply {
                visibility = View.VISIBLE
                onClick {
                    closed = true
                    val wasSelected = Store.selectedId(this@ProfileActivity) == this@ProfileActivity.id
                    Store.delete(this@ProfileActivity, this@ProfileActivity.id!!)
                    if (wasSelected) reconnect()
                    finish()
                }
            }
        } else {
            scanQr.apply {
                visibility = View.VISIBLE
                onClick {
                    startActivityForResult(Intent(this@ProfileActivity, QrScanActivity::class.java), REQ_QR_SCAN)
                }
            }
        }
        save.onClick { save() }
    }

    override fun onDestroy() {
        closed = true
        super.onDestroy()
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_QR_SCAN && resultCode == RESULT_OK) {
            finish()
        }
    }

    private fun field(id: Int): EditText = findViewById(id)

    private fun text(id: Int): String = field(id).text.toString()

    private fun save() {
        error.visibility = View.GONE
        save.isEnabled = false
        scanQr.isEnabled = false
        showQr.isEnabled = false
        delete.isEnabled = false
        val vless = kind.checkedRadioButtonId == R.id.kind_vless
        val pasted = link.text.toString().trim()
        val proxyKind = if (kind.checkedRadioButtonId == R.id.kind_http) "http" else "socks5"
        val form = listOf(R.id.name, R.id.host, R.id.port, R.id.user, R.id.pass).map(::text)
        thread {
            val failure = try {
                ProfileImporter.importForm(
                    this,
                    vless,
                    pasted,
                    proxyKind,
                    form[0],
                    form[1],
                    form[2].trim().toLongOrNull() ?: 0,
                    form[3],
                    form[4],
                    id,
                )
                null
            } catch (e: Exception) {
                e.message ?: e.javaClass.simpleName
            }
            runOnUiThread {
                if (closed || isFinishing || isDestroyed) return@runOnUiThread
                if (failure == null) {
                    finish()
                } else {
                    save.isEnabled = true
                    scanQr.isEnabled = true
                    showQr.isEnabled = true
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
}
