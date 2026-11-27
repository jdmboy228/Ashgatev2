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
    private var installedApps: Set<String>? = null

    /** A check before connecting that failed; shown until the next try. */
    private var notice: String? = null

    /** Color of the status word and dot now; state changes fade from it. */
    private var statusColor = 0
    private var colorAnim: ValueAnimator? = null

    /** The dot breathes while connecting. */
    private var pulse: ObjectAnimator? = null

    /** Between onStart and onStop: a late state callback must not start the pulse on a hidden screen. */
    private var visible = false

    @Volatile
    private var loading = false
    private var afterLoad: (() -> Unit)? = null

    private val onState: () -> Unit = { runOnUiThread { showState(animate = true) } }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        notice = savedInstanceState?.getString("notice")
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
        findViewById<TextView>(R.id.version).apply {
            typeface = Fonts.mono(this@MainActivity)
            val v = try {
                packageManager.getPackageInfo(packageName, 0).versionName
            } catch (e: Exception) {
                null
            }
            if (!v.isNullOrEmpty()) text = "v$v"
        }

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
        findViewById<View>(R.id.row_profile).onClick { open(ProfilesActivity::class.java) }
        findViewById<View>(R.id.row_apps).onClick { open(AppsActivity::class.java) }
    }

    private fun open(screen: Class<out Activity>) {
        if (Store.isOpen) {
            startActivity(Intent(this, screen))
        } else {
            afterLoad = { startActivity(Intent(this, screen)) }
            loadInBackground()
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString("notice", notice)
    }

    override fun onStart() {
        super.onStart()
        visible = true
        TunnelService.listener = onState
        showRows()
        showState(animate = false)
        loadInBackground()
    }

    /** Opening the saved data (the Keystore) and listing the apps both take a moment. */
    private fun loadInBackground() {
        if (loading) return
        loading = true
        thread {
            val usable = Store.usable(this)
            // The same list the app picker shows, cached after the first scan.
            val installed = try {
                AppsActivity.installedPackages(this)
            } catch (e: Exception) {
                null
            }
            runOnUiThread {
                loading = false
                if (isFinishing || isDestroyed) return@runOnUiThread
                if (installed != null) {
                    installedApps = installed
                    appsTotal = installed.size
                }
                val pending = afterLoad
                afterLoad = null
                val unavailable = getString(R.string.store_unavailable)
                if (!usable) {
                    notice = unavailable
                } else {
                    // A notice whose cause was fixed elsewhere (a profile or apps picked) goes away.
                    if (notice == unavailable ||
                        notice == getString(R.string.need_profile) && Store.selected(this) != null ||
                        notice == getString(R.string.need_apps) && pickedAppsCount() > 0
                    ) {
                        notice = null
                    }
                    if (visible && Store.takeWiped(this)) notice = getString(R.string.store_wiped)
                }
                showRows()
                showState(animate = false)
                if (usable && visible) pending?.invoke()
            }
        }
    }

    override fun onStop() {
        visible = false
        afterLoad = null
        // A newer main screen may already have put its own listener here.
        if (TunnelService.listener === onState) TunnelService.listener = null
        pulse?.cancel()
        pulse = null
        colorAnim?.cancel()
        colorAnim = null
        glow.animate().cancel()
        dot.alpha = 1f
        super.onStop()
    }

    private fun pickedAppsCount(): Int {
        if (!Store.isOpen) return 0
        val picked = Store.apps(this)
        val installed = installedApps ?: return picked.size
        return picked.count { it in installed }
    }

    private fun showRows() {
        if (!Store.isOpen) return
        profile.text = Store.selected(this)?.optString("name") ?: getString(R.string.need_profile)
        val n = pickedAppsCount()
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
        swap(status, word.uppercase(Locale.forLanguageTag("ru")), null, animate)
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

        val message = when (state) {
            State.OFF -> notice ?: TunnelService.error
            // Why the tunnel is down while the picked apps are cut off.
            State.BLOCKED -> TunnelService.error ?: getString(R.string.blocked_note)
            else -> null
        }
        // Until the saved data is open only a message can be shown.
        val n = pickedAppsCount()
        val text = when {
            message != null -> message
            !Store.isOpen -> return
            state != State.OFF -> RuPlural.pick(resources.getStringArray(R.array.sub_on), n).format(n)
            Store.profiles(this).isEmpty() -> getString(R.string.no_profiles)
            else -> RuPlural.pick(resources.getStringArray(R.array.sub_off), n).format(n)
        }
        swap(sub, text, getColor(if (message != null) R.color.ag_error else R.color.ag_text2), animate)
    }

    /** Sets [text] (and [color]); a change fades out and back in. */
    private fun swap(view: TextView, text: String, color: Int?, animate: Boolean) {
        val targetColor = color ?: view.currentTextColor
        val targetKey = "$text#$targetColor"
        val same = view.text.toString() == text && (color == null || view.currentTextColor == color)
        if (same && view.alpha == 1f) {
            view.tag = targetKey
            return
        }
        if (animate && view.tag == targetKey) return
        view.tag = targetKey
        view.animate().withEndAction(null).cancel()
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
            if (view.tag != targetKey) return@withEndAction
            apply()
            view.animate().withEndAction(null).alpha(1f).setDuration(150).start()
        }.start()
    }

    private fun showStatusColor(color: Int, animate: Boolean) {
        colorAnim?.cancel()
        val paint: (Int) -> Unit = { c ->
            statusColor = c
            status.setTextColor(c)
            (dot.background.mutate() as? GradientDrawable)?.setColor(c)
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
        if (!Store.isOpen) {
            afterLoad = { connect() }
            return loadInBackground()
        }
        notice = when {
            Store.selected(this) == null -> getString(R.string.need_profile)
            pickedAppsCount() == 0 -> getString(R.string.need_apps)
            else -> null
        }
        if (notice != null) return showState(animate = true)
        try {
            val consent = VpnService.prepare(this)
            if (consent != null) {
                startActivityForResult(consent, 1)
            } else {
                startTunnel()
            }
        } catch (e: Exception) {
            // Some firmwares have no consent screen, or fail in prepare().
            notice = getString(R.string.no_vpn_permission)
            showState(animate = true)
        }
    }

    private fun startTunnel() {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            // Requested only after VPN consent is settled so two system dialogs never race.
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 0)
        }
        TunnelService.connect(this)
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode != 1) return
        if (resultCode == RESULT_OK) {
            startTunnel()
        } else {
            notice = getString(R.string.no_vpn_permission)
            showState(animate = true)
        }
    }
}
