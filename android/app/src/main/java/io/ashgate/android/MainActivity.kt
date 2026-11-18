package io.ashgate.android

import android.Manifest
import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.GradientDrawable
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.animation.AccelerateDecelerateInterpolator
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

    /** Color of the status word and dot now; state changes fade from it. */
    private var statusColor = 0
    private var colorAnim: ValueAnimator? = null

    /** The dot breathes while connecting. */
    private var pulse: ObjectAnimator? = null

    /** Between onStart and onStop: a late state callback must not start the pulse on a hidden screen. */
    private var visible = false

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

        // A quick second tap would connect twice or connect right after disconnecting.
        findViewById<View>(R.id.toggle).onClick {
            if (TunnelService.state == State.OFF) connect() else TunnelService.disconnect(this)
        }
        findViewById<View>(R.id.row_profile).onClick {
            startActivity(Intent(this, ProfilesActivity::class.java))
        }
        findViewById<View>(R.id.row_apps).onClick {
            startActivity(Intent(this, AppsActivity::class.java))
        }
    }

    override fun onStart() {
        super.onStart()
        visible = true
        TunnelService.listener = { runOnUiThread { showState(animate = true) } }
        // A notice whose cause was fixed on another screen (a profile or apps picked) goes away.
        if (notice == getString(R.string.need_profile) && Store.selected(this) != null ||
            notice == getString(R.string.need_apps) && Store.apps(this).isNotEmpty()
        ) {
            notice = null
        }
        if (Store.takeWiped(this)) notice = getString(R.string.store_wiped)
        showRows()
        showState(animate = false)
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
        visible = false
        TunnelService.listener = null
        pulse?.cancel()
        pulse = null
        super.onStop()
    }

    private fun showRows() {
        profile.text = Store.selected(this)?.optString("name") ?: getString(R.string.need_profile)
        val n = Store.apps(this).size
        apps.text = appsTotal?.let { getString(R.string.apps_of, n, it) } ?: n.toString()
    }

    private fun showState(animate: Boolean) {
        val state = TunnelService.state
        val word = getString(
            when (state) {
                State.OFF -> R.string.state_off
                State.STARTING -> R.string.state_starting
                State.ON -> R.string.state_on
                State.BLOCKED -> R.string.state_blocked
            },
        )
        swap(status, word.uppercase(Locale("ru")), null, animate)
        showStatusColor(
            getColor(
                when (state) {
                    State.OFF -> R.color.ag_text3
                    State.STARTING -> R.color.ag_text2
                    State.ON -> R.color.ag_success
                    State.BLOCKED -> R.color.ag_error
                },
            ),
            animate,
        )
        // Not when animations are off in the system settings: an endless animation would stay frozen.
        showPulse(
            visible && state == State.STARTING && (Build.VERSION.SDK_INT < 26 || ValueAnimator.areAnimatorsEnabled()),
        )
        showGlow(state == State.ON, animate)
        swap(
            title,
            getString(
                when (state) {
                    State.OFF -> R.string.title_off
                    State.STARTING -> R.string.title_starting
                    State.ON -> R.string.title_on
                    State.BLOCKED -> R.string.title_blocked
                },
            ),
            null,
            animate,
        )
        swap(toggleText, getString(if (state == State.OFF) R.string.connect else R.string.disconnect), null, animate)

        val n = Store.apps(this).size
        val message = when (state) {
            State.OFF -> notice ?: TunnelService.error
            // Why the tunnel is down while the picked apps are cut off.
            State.BLOCKED -> TunnelService.error ?: getString(R.string.blocked_note)
            else -> null
        }
        val text = when {
            message != null -> message
            state != State.OFF -> RuPlural.pick(resources.getStringArray(R.array.sub_on), n).format(n)
            Store.profiles(this).isEmpty() -> getString(R.string.no_profiles)
            else -> RuPlural.pick(resources.getStringArray(R.array.sub_off), n).format(n)
        }
        swap(sub, text, getColor(if (message != null) R.color.ag_error else R.color.ag_text2), animate)
    }

    /** Sets [text] (and [color]); a change fades out and back in. */
    private fun swap(view: TextView, text: String, color: Int?, animate: Boolean) {
        val same = view.text.toString() == text && (color == null || view.currentTextColor == color)
        if (same && view.alpha == 1f) return
        view.animate().cancel()
        val apply = {
            view.text = text
            if (color != null) view.setTextColor(color)
        }
        if (!animate || same) {
            apply()
            view.alpha = 1f
            return
        }
        view.animate().alpha(0f).setDuration(100).withEndAction {
            apply()
            view.animate().alpha(1f).setDuration(150).start()
        }.start()
    }

    private fun showStatusColor(color: Int, animate: Boolean) {
        colorAnim?.cancel()
        val paint = { c: Int ->
            statusColor = c
            status.setTextColor(c)
            (dot.background.mutate() as GradientDrawable).setColor(c)
        }
        if (!animate || statusColor == 0 || statusColor == color) return paint(color)
        colorAnim = ValueAnimator.ofArgb(statusColor, color).apply {
            duration = 250
            addUpdateListener { paint(it.animatedValue as Int) }
            start()
        }
    }

    private fun showPulse(on: Boolean) {
        if (on == (pulse != null)) return
        pulse?.cancel()
        pulse = null
        dot.alpha = 1f
        if (!on) return
        pulse = ObjectAnimator.ofFloat(dot, View.ALPHA, 1f, 0.3f).apply {
            duration = 700
            repeatMode = ValueAnimator.REVERSE
            repeatCount = ValueAnimator.INFINITE
            interpolator = AccelerateDecelerateInterpolator()
            start()
        }
    }

    private fun showGlow(on: Boolean, animate: Boolean) {
        glow.animate().cancel()
        if (!animate) {
            glow.alpha = 1f
            glow.visibility = if (on) View.VISIBLE else View.GONE
            return
        }
        if (on) {
            if (glow.visibility != View.VISIBLE) {
                glow.alpha = 0f
                glow.visibility = View.VISIBLE
            }
            glow.animate().alpha(1f).setDuration(300).start()
        } else if (glow.visibility == View.VISIBLE) {
            glow.animate().alpha(0f).setDuration(250).withEndAction { glow.visibility = View.GONE }.start()
        }
    }

    private fun connect() {
        notice = when {
            Store.selected(this) == null -> getString(R.string.need_profile)
            Store.apps(this).isEmpty() -> getString(R.string.need_apps)
            else -> null
        }
        if (notice != null) return showState(animate = true)
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
            showState(animate = true)
        }
    }
}
