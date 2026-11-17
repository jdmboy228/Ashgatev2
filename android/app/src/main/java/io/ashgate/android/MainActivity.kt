package io.ashgate.android

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.GradientDrawable
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.TextView
import io.ashgate.android.TunnelService.State
import java.util.Locale
import kotlin.concurrent.thread

/** Status, the connect button, and the ways to the profiles and the app picker. */
class MainActivity : Activity() {
    private lateinit var glow: View
    private lateinit var dot: View
    private lateinit var status: TextView
    private lateinit var title: TextView
    private lateinit var sub: TextView
    private lateinit var profile: TextView
    private lateinit var apps: TextView
    private lateinit var toggleText: TextView

    /** Apps with a launcher icon, counted in the background; null until then. */
    private var appsTotal: Int? = null

    /** A check before connecting that failed; shown until the next try. */
    private var notice: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.main)
        glow = findViewById(R.id.glow)
        dot = findViewById(R.id.dot)
        status = findViewById(R.id.status)
        title = findViewById(R.id.title)
        sub = findViewById(R.id.sub)
        profile = findViewById(R.id.profile)
        apps = findViewById(R.id.apps)
        toggleText = findViewById(R.id.toggle_text)

        Fonts.set(Fonts.monoSemibold(this), status)
        Fonts.set(Fonts.extrabold(this), title, toggleText)
        Fonts.set(Fonts.medium(this), sub, findViewById(R.id.label_profile), findViewById(R.id.label_apps),
            findViewById(R.id.label_russia))
        Fonts.set(Fonts.bold(this), profile, apps, findViewById(R.id.russia))

        // Blur needs API 31, so the glow is a radial gradient fading out to its edge.
        glow.background = GradientDrawable().apply {
            gradientType = GradientDrawable.RADIAL_GRADIENT
            gradientRadius = 200 * resources.displayMetrics.density
            colors = intArrayOf(0x1A5FD38D, 0x0D5FD38D, 0x005FD38D)
        }

        findViewById<View>(R.id.toggle).setOnClickListener {
            if (TunnelService.state == State.OFF) connect() else TunnelService.disconnect(this)
        }
        findViewById<View>(R.id.row_profile).setOnClickListener {
            startActivity(Intent(this, ProfilesActivity::class.java))
        }
        findViewById<View>(R.id.row_apps).setOnClickListener {
            startActivity(Intent(this, AppsActivity::class.java))
        }
    }

    override fun onStart() {
        super.onStart()
        TunnelService.listener = { runOnUiThread { showState() } }
        showRows()
        showState()
        // The same list the app picker shows; reading it takes a moment.
        thread {
            val total = AppsActivity.launcherApps(this).size
            runOnUiThread {
                appsTotal = total
                showRows()
            }
        }
    }

    override fun onStop() {
        TunnelService.listener = null
        super.onStop()
    }

    private fun showRows() {
        profile.text = Store.selected(this)?.optString("name") ?: getString(R.string.need_profile)
        val n = Store.apps(this).size
        apps.text = appsTotal?.let { getString(R.string.apps_of, n, it) } ?: n.toString()
    }

    private fun showState() {
        val state = TunnelService.state
        val word = getString(
            when (state) {
                State.OFF -> R.string.state_off
                State.STARTING -> R.string.state_starting
                State.ON -> R.string.state_on
            },
        )
        status.text = word.uppercase(Locale("ru"))
        val color = getColor(
            when (state) {
                State.OFF -> R.color.ag_text3
                State.STARTING -> R.color.ag_text2
                State.ON -> R.color.ag_success
            },
        )
        status.setTextColor(color)
        (dot.background.mutate() as GradientDrawable).setColor(color)
        glow.visibility = if (state == State.ON) View.VISIBLE else View.GONE
        title.setText(
            when (state) {
                State.OFF -> R.string.title_off
                State.STARTING -> R.string.title_starting
                State.ON -> R.string.title_on
            },
        )
        toggleText.setText(if (state == State.OFF) R.string.connect else R.string.disconnect)

        val n = Store.apps(this).size
        val message = if (state == State.OFF) notice ?: TunnelService.error else null
        sub.text = when {
            message != null -> message
            state != State.OFF -> resources.getQuantityString(R.plurals.sub_on, n, n)
            Store.profiles(this).isEmpty() -> getString(R.string.no_profiles)
            else -> resources.getQuantityString(R.plurals.sub_off, n, n)
        }
        sub.setTextColor(getColor(if (message != null) R.color.ag_error else R.color.ag_text2))
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
