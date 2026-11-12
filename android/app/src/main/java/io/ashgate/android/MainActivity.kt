package io.ashgate.android

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.ListView
import android.widget.TextView
import io.ashgate.android.TunnelService.State
import org.json.JSONObject

/** Status, the connect button, the profile list and the way to the app picker. */
class MainActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var error: TextView
    private lateinit var toggle: Button
    private lateinit var list: ListView
    private lateinit var hint: TextView
    private lateinit var apps: Button
    private var profiles: List<JSONObject> = emptyList()

    /** A check before connecting that failed; shown until the next try. */
    private var notice: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.main)
        status = findViewById(R.id.status)
        error = findViewById(R.id.error)
        toggle = findViewById(R.id.toggle)
        list = findViewById(R.id.list)
        hint = findViewById(R.id.hint)
        apps = findViewById(R.id.apps)

        toggle.setOnClickListener {
            if (TunnelService.state == State.OFF) connect() else TunnelService.disconnect(this)
        }
        findViewById<Button>(R.id.add).setOnClickListener {
            startActivity(Intent(this, ProfileActivity::class.java))
        }
        apps.setOnClickListener { startActivity(Intent(this, AppsActivity::class.java)) }
        list.setOnItemClickListener { _, _, position, _ ->
            val id = profiles[position].getString("id")
            if (id == Store.selectedId(this)) return@setOnItemClickListener
            Store.select(this, id)
            // A running tunnel moves to the new profile.
            if (TunnelService.state != State.OFF) TunnelService.connect(this)
        }
        list.setOnItemLongClickListener { _, _, position, _ ->
            startActivity(
                Intent(this, ProfileActivity::class.java).putExtra("id", profiles[position].getString("id")),
            )
            true
        }
    }

    override fun onStart() {
        super.onStart()
        TunnelService.listener = { runOnUiThread { showState() } }
        showProfiles()
        showState()
    }

    override fun onStop() {
        TunnelService.listener = null
        super.onStop()
    }

    private fun showProfiles() {
        profiles = Store.profiles(this)
        list.adapter = ArrayAdapter(
            this, android.R.layout.simple_list_item_single_choice, profiles.map(::title),
        )
        val selected = profiles.indexOfFirst { it.getString("id") == Store.selectedId(this) }
        if (selected >= 0) list.setItemChecked(selected, true)
        hint.setText(if (profiles.isEmpty()) R.string.no_profiles else R.string.edit_hint)
        apps.text = getString(R.string.apps_count, Store.apps(this).size)
    }

    private fun title(p: JSONObject): String {
        val kind = when (p.optString("kind")) {
            "vless" -> "VLESS XHTTP"
            "socks5" -> "SOCKS5"
            else -> "HTTP"
        }
        return "${p.optString("name")} · $kind"
    }

    private fun showState() {
        val state = TunnelService.state
        status.setText(
            when (state) {
                State.OFF -> R.string.state_off
                State.STARTING -> R.string.state_starting
                State.ON -> R.string.state_on
            },
        )
        toggle.setText(if (state == State.OFF) R.string.connect else R.string.disconnect)
        val message = if (state == State.OFF) notice ?: TunnelService.error else null
        error.text = message
        error.visibility = if (message == null) View.GONE else View.VISIBLE
    }

    private fun connect() {
        notice = when {
            Store.selected(this) == null -> getString(R.string.need_profile)
            Store.apps(this).isEmpty() -> getString(R.string.need_apps)
            else -> null
        }
        if (notice != null) return showState()
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            // For the "connected" notification; the tunnel works without it.
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 0)
        }
        val consent = VpnService.prepare(this)
        if (consent != null) startActivityForResult(consent, 1) else TunnelService.connect(this)
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode != 1) return
        if (resultCode == RESULT_OK) {
            TunnelService.connect(this)
        } else {
            notice = getString(R.string.no_vpn_permission)
            showState()
        }
    }
}
