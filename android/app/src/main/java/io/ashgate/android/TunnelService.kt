package io.ashgate.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import io.ashgate.mobile.Mobile
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException

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

    // One thread: connects and disconnects never overlap.
    private val worker = Executors.newSingleThreadExecutor()

    /** The VPN interface; touched only on [worker]. */
    private var tun: ParcelFileDescriptor? = null

    /** The real network Ashgate (outside the tunnel) uses; a change restarts Xray. */
    private var network: Network? = null
    private var watching: ConnectivityManager.NetworkCallback? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == DISCONNECT) {
            worker.execute { stop(null) }
        } else {
            // Also RETRY from the notification, and the system's start of an always-on VPN.
            worker.execute { start() }
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        // The system has already taken the interface away (another VPN app, or the user in settings).
        later { stop(getString(R.string.vpn_revoked)) }
    }

    /** Runs on [worker]; a callback that arrives after onDestroy is dropped. */
    private fun later(block: () -> Unit) {
        try {
            worker.execute(block)
        } catch (e: RejectedExecutionException) {
        }
    }

    override fun onDestroy() {
        worker.execute {
            unwatch()
            close()
            set(State.OFF, error)
        }
        worker.shutdown()
        super.onDestroy()
    }

    /**
     * Brings the tunnel up, or moves a running one to the current profile and
     * apps. The new interface is established before the old one is closed:
     * Android swaps them in one step, so the picked apps never have a moment
     * outside the tunnel.
     */
    private fun start() {
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
        try {
            // Stops the previous Xray, if any, and starts one on the new interface.
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
        watch() // a new network retries by itself
        foreground(blocked = true)
        set(State.BLOCKED, reason)
    }

    private fun stop(reason: String?) {
        unwatch()
        close()
        set(State.OFF, reason)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
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
     * The restart keeps the interface (see [start]), so nothing leaks.
     */
    private fun watch() {
        if (watching != null) return
        val manager = getSystemService(ConnectivityManager::class.java)
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(n: Network) {
                later {
                    val previous = network
                    network = n
                    if (watching != null && previous != null && previous != n && state != State.OFF) start()
                }
            }
        }
        try {
            manager.registerDefaultNetworkCallback(callback)
            watching = callback
        } catch (e: Exception) {
            // Too many callbacks registered system-wide; the tunnel works without it.
        }
    }

    private fun unwatch() {
        val callback = watching ?: return
        watching = null
        network = null
        try {
            getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(callback)
        } catch (e: Exception) {
        }
    }

    /** Copies geoip.dat and geosite.dat out of the APK once per installed build. */
    private fun geodata(): File {
        val dir = File(filesDir, "geo")
        val stamp = File(dir, "stamp")
        val build = packageManager.getPackageInfo(packageName, 0).lastUpdateTime.toString()
        if (stamp.exists() && stamp.readText() == build) return dir
        dir.mkdirs()
        for (name in listOf("geoip.dat", "geosite.dat")) {
            assets.open(name).use { input ->
                File(dir, name).outputStream().use { input.copyTo(it) }
            }
        }
        stamp.writeText(build)
        return dir
    }

    private fun foreground(blocked: Boolean) {
        val manager = getSystemService(NotificationManager::class.java)
        val builder = if (Build.VERSION.SDK_INT >= 26) {
            manager.createNotificationChannel(
                NotificationChannel("tunnel", getString(R.string.channel), NotificationManager.IMPORTANCE_LOW),
            )
            Notification.Builder(this, "tunnel")
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), flags)
        val off = PendingIntent.getService(
            this, 1, Intent(this, TunnelService::class.java).setAction(DISCONNECT), flags,
        )
        builder
            .setSmallIcon(R.drawable.ic_stat)
            .setContentIntent(open)
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
                startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
            } else {
                startForeground(1, notification)
            }
        } catch (e: Exception) {
            // The system keeps a connected VpnService alive without it.
        }
    }
}
