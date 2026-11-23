package io.ashgate.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import io.ashgate.mobile.Mobile
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/**
 * The tunnel. Only the apps the user picked are routed into the TUN
 * (addAllowedApplication); Ashgate itself is never one of them, so Xray's
 * own connections leave through the real network without protect().
 *
 * The TUN takes every IPv4 and IPv6 route and the DNS server of those apps,
 * so nothing of theirs has a path around it. Xray reads the descriptor
 * itself (its TUN inbound); there is no local proxy port.
 */
class TunnelService : VpnService() {
    /**
     * BLOCKED: the tunnel failed after it was up, or a reconnect failed. The
     * VPN interface stays, without Xray behind it, so the picked apps have
     * no network at all instead of going around the tunnel. Only
     * «Отключить» (or a working reconnect) ends it.
     */
    enum class State { OFF, STARTING, ON, BLOCKED }

    companion object {
        private const val DISCONNECT = "io.ashgate.android.DISCONNECT"
        private const val RETRY = "io.ashgate.android.RETRY"
        private const val NOTE_TUNNEL = 1
        private const val NOTE_DOWN = 2

        /** Changes that come together (a network flapping, quick taps) make one restart. */
        private const val RESTART_DELAY_MS = 1000L

        /**
         * One thread for every instance of the service, as the Go core is one
         * per process: connects and disconnects never overlap, even when a
         * new instance starts while the old one is being cleaned up.
         */
        private val worker = Executors.newSingleThreadScheduledExecutor()

        /** The executor would keep an exception to itself. Only its type is logged: messages may quote a server. */
        private fun onWorker(block: () -> Unit) {
            worker.execute {
                try {
                    block()
                } catch (e: Exception) {
                    Log.e("Ashgate", "tunnel task failed: " + e.javaClass.name)
                }
            }
        }

        @Volatile
        var state = State.OFF
            private set

        /** Why the last connect failed, for the main screen. */
        @Volatile
        var error: String? = null
            private set

        /** Called on any thread when state or error changes. */
        @Volatile
        var listener: (() -> Unit)? = null

        fun connect(ctx: Context) {
            ctx.startService(Intent(ctx, TunnelService::class.java))
        }

        fun disconnect(ctx: Context) {
            ctx.startService(Intent(ctx, TunnelService::class.java).setAction(DISCONNECT))
        }

        private fun set(s: State, e: String? = null) {
            state = s
            error = e
            listener?.invoke()
        }
    }

    /** The VPN interface; touched only on [worker], like the fields below. */
    private var tun: ParcelFileDescriptor? = null

    /** The real network Ashgate (outside the tunnel) uses; a change restarts Xray. */
    private var network: Network? = null
    private var watching: ConnectivityManager.NetworkCallback? = null
    private var installs: BroadcastReceiver? = null

    /** The restart waiting to run, and whether it must rebuild the interface too. */
    private var restart: ScheduledFuture<*>? = null
    private var restartFull = false

    /** Set once this instance is cleaned up: what it scheduled no longer runs. */
    private var destroyed = false

    /** The newest start request processed on [worker], so that stopping never drops one that just came. */
    private var lastStartId = 0

    /** True once the system started or restarted the tunnel without the user on screen, so a failure notifies. */
    private var expectedUp = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val disconnect = intent?.action == DISCONNECT
        val systemStart = intent == null || intent.action == SERVICE_INTERFACE
        onWorker {
            lastStartId = startId
            if (systemStart) expectedUp = true
            when {
                disconnect -> stop(null)
                // Also RETRY from the notification, the system's start of an
                // always-on VPN, and its restart after the process died (no intent):
                // explicit starts and profile/app changes run at once, without the
                // network-flap delay.
                else -> {
                    cancelRestart()
                    start()
                }
            }
        }
        // If the process dies the interface goes with it and the picked apps
        // are outside the tunnel: the system must bring the service back.
        return START_STICKY
    }

    override fun onRevoke() {
        // The system has already taken the interface away (another VPN app, or the user in settings).
        later { stop(getString(R.string.vpn_revoked)) }
    }

    /** Runs on [worker]; a callback that arrives after onDestroy is dropped. */
    private fun later(block: () -> Unit) {
        onWorker { if (!destroyed) block() }
    }

    override fun onDestroy() {
        onWorker {
            destroyed = true
            cancelRestart()
            unwatch()
            close()
            set(State.OFF, error)
        }
        super.onDestroy()
    }

    /** One restart for network changes that arrive within [RESTART_DELAY_MS]. Runs on [worker]. */
    private fun restartSoon(full: Boolean) {
        restartFull = restartFull || full
        if (restart != null) return
        restart = worker.schedule(
            Runnable {
                if (destroyed) return@Runnable
                restart = null
                val rebuild = restartFull || tun == null
                restartFull = false
                if (rebuild) start() else guarded { restartXray() }
            },
            RESTART_DELAY_MS,
            TimeUnit.MILLISECONDS,
        )
    }

    private fun cancelRestart() {
        restart?.cancel(false)
        restart = null
        restartFull = false
    }

    /** Saved data that cannot be read must not end the process, and the tunnel with it. */
    private inline fun guarded(block: () -> Unit) {
        try {
            block()
        } catch (e: Exception) {
            fail(getString(R.string.store_unavailable))
        }
    }

    /**
     * Brings the tunnel up, or moves a running one to the current profile and
     * apps. The new interface is established before the old one is closed:
     * Android swaps them in one step, so the picked apps never have a moment
     * outside the tunnel.
     */
    private fun start() {
        guarded { bringUp() }
    }

    private fun bringUp() {
        set(State.STARTING)
        val profile = Store.selected(this) ?: return fail(getString(R.string.need_profile))
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(Mobile.Mtu.toInt())
            .addAddress("10.111.222.1", 30)
            .addAddress("fd6f:a5b9:7e11::1", 126)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            // Any address works: Xray answers port 53 itself, through the tunnel.
            .addDnsServer("1.1.1.1")
        // false = take the meteredness of the real network (true would always say metered).
        if (Build.VERSION.SDK_INT >= 29) builder.setMetered(false)
        var allowed = 0
        for (pkg in Store.apps(this)) {
            if (pkg == packageName) continue
            try {
                builder.addAllowedApplication(pkg)
                allowed++
            } catch (e: PackageManager.NameNotFoundException) {
                // Uninstalled since it was picked.
            }
        }
        // With no allowed app the VPN would take every app, Ashgate included.
        if (allowed == 0) return fail(getString(R.string.need_apps))
        var fd: ParcelFileDescriptor? = null
        try {
            fd = builder.establish()
        } catch (e: Exception) {
            return fail(e.message ?: e.javaClass.simpleName)
        }
        // null: the VPN permission was taken away, and the old interface with it.
        if (fd == null) return stop(getString(R.string.no_vpn_permission))
        val old = tun
        tun = fd
        closeQuietly(old)
        runXray(profile, fd)
    }

    /** A new Xray on the interface that is up, which stays: nothing leaks meanwhile. */
    private fun restartXray() {
        val fd = tun ?: return
        set(State.STARTING)
        val profile = Store.selected(this) ?: return fail(getString(R.string.need_profile))
        runXray(profile, fd)
    }

    private fun runXray(profile: JSONObject, fd: ParcelFileDescriptor) {
        try {
            // Stops the previous Xray, if any, and starts one on this interface.
            Mobile.start(profile.toString(), fd.fd.toLong(), geodata().path)
        } catch (e: Exception) {
            return fail(e.message ?: e.javaClass.simpleName)
        }
        watch()
        foreground(blocked = false)
        set(State.ON)
    }

    /**
     * A start that failed. If the VPN interface is up, it stays up without
     * Xray: the picked apps are cut off rather than sent around the tunnel.
     * With no interface yet nothing can leak, so the service just ends.
     */
    private fun fail(reason: String) {
        if (tun == null) return stop(reason)
        Mobile.stop()
        // First: the screen must say so whatever happens below.
        set(State.BLOCKED, reason)
        watch() // a new network retries by itself
        foreground(blocked = true)
    }

    private fun stop(reason: String?) {
        val wasUp = tun != null || expectedUp
        expectedUp = false
        cancelRestart()
        unwatch()
        close()
        set(State.OFF, reason)
        stopForeground(STOP_FOREGROUND_REMOVE)
        // Not asked for by the user: the picked apps are outside the tunnel now.
        if (reason != null && wasUp) notifyDown()
        stopSelf(lastStartId)
    }

    private fun close() {
        Mobile.stop()
        closeQuietly(tun)
        tun = null
    }

    private fun closeQuietly(fd: ParcelFileDescriptor?) {
        try {
            fd?.close()
        } catch (e: Exception) {
        }
    }

    /**
     * Restarts Xray when the real network changes (Wi-Fi to mobile data and
     * back): connections of the old network would hang until they time out.
     * The restart keeps the interface (see [restartXray]), so nothing leaks.
     * It also rebuilds the tunnel when a picked app is installed: the
     * interface admits apps by uid, and a new install has a new one.
     */
    private fun watch() {
        watchInstalls()
        if (watching != null) return
        val manager = getSystemService(ConnectivityManager::class.java)
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(n: Network) {
                later {
                    val previous = network
                    network = n
                    if (watching != null && previous != n && state != State.OFF) restartSoon(full = false)
                }
            }
        }
        try {
            // The callback first reports the current network, which is no change.
            network = manager.activeNetwork
            manager.registerDefaultNetworkCallback(callback)
            watching = callback
        } catch (e: Exception) {
            // Too many callbacks registered system-wide; the tunnel works without it.
        }
    }

    private fun watchInstalls() {
        if (installs != null) return
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                // An update keeps the uid.
                if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
                val pkg = intent.data?.schemeSpecificPart ?: return
                later {
                    if (tun != null && pkg in Store.apps(this@TunnelService)) {
                        cancelRestart()
                        start()
                    }
                }
            }
        }
        val filter = IntentFilter(Intent.ACTION_PACKAGE_ADDED).apply { addDataScheme("package") }
        try {
            if (Build.VERSION.SDK_INT >= 33) {
                registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                registerReceiver(receiver, filter)
            }
            installs = receiver
        } catch (e: Exception) {
            // Too many receivers in the process; the tunnel works without it.
        }
    }

    private fun unwatch() {
        installs?.let { unregisterReceiver(it) }
        installs = null
        val callback = watching ?: return
        watching = null
        network = null
        try {
            getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(callback)
        } catch (e: Exception) {
        }
    }

    /** Copies geosite.dat out of the APK once per installed build. */
    private fun geodata(): File {
        val dir = File(filesDir, "geo")
        val stamp = File(dir, "stamp")
        val build = packageManager.getPackageInfo(packageName, 0).lastUpdateTime.toString()
        if (stamp.exists() && stamp.readText() == build) return dir
        dir.mkdirs()
        for (name in listOf("geosite.dat")) {
            assets.open(name).use { input ->
                File(dir, name).outputStream().use { input.copyTo(it) }
            }
        }
        stamp.writeText(build)
        return dir
    }

    @Suppress("DEPRECATION")
    private fun notificationBuilder(channel: String, name: Int, importance: Int): Notification.Builder {
        if (Build.VERSION.SDK_INT < 26) return Notification.Builder(this)
        getSystemService(NotificationManager::class.java)
            .createNotificationChannel(NotificationChannel(channel, getString(name), importance))
        return Notification.Builder(this, channel)
    }

    /** Back to the main screen that is already open, instead of a second one on top. */
    private fun openApp(): PendingIntent = PendingIntent.getActivity(
        this,
        0,
        Intent(this, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
    )

    /** The tunnel ended without the user asking; the app may not be on screen. */
    private fun notifyDown() {
        val notification = notificationBuilder("alerts", R.string.channel_alerts, NotificationManager.IMPORTANCE_DEFAULT)
            .setSmallIcon(R.drawable.ic_stat)
            .setContentTitle(getString(R.string.title_off))
            .setContentText(getString(R.string.tunnel_down_note))
            .setContentIntent(openApp())
            .setAutoCancel(true)
            .build()
        getSystemService(NotificationManager::class.java).notify(NOTE_DOWN, notification)
    }

    private fun foreground(blocked: Boolean) {
        getSystemService(NotificationManager::class.java).cancel(NOTE_DOWN)
        val builder = notificationBuilder("tunnel", R.string.channel, NotificationManager.IMPORTANCE_LOW)
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        val off = PendingIntent.getService(
            this, 1, Intent(this, TunnelService::class.java).setAction(DISCONNECT), flags,
        )
        builder
            .setSmallIcon(R.drawable.ic_stat)
            .setContentIntent(openApp())
            .setOngoing(true)
        if (blocked) {
            val retry = PendingIntent.getService(
                this, 2, Intent(this, TunnelService::class.java).setAction(RETRY), flags,
            )
            builder.setContentTitle(getString(R.string.state_blocked))
                .setContentText(getString(R.string.blocked_note))
                .addAction(Notification.Action.Builder(null, getString(R.string.retry), retry).build())
        } else {
            builder.setContentTitle(getString(R.string.state_on))
                .setContentText(Store.selected(this)?.optString("name"))
        }
        val notification = builder
            .addAction(Notification.Action.Builder(null, getString(R.string.disconnect), off).build())
            .build()
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTE_TUNNEL, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
            } else {
                startForeground(NOTE_TUNNEL, notification)
            }
        } catch (e: Exception) {
            // The system keeps a connected VpnService alive without it.
        }
    }
}
