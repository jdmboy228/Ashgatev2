package io.ashgate.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import io.ashgate.mobile.Mobile
import java.io.File
import java.util.concurrent.Executors

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
    enum class State { OFF, STARTING, ON }

    companion object {
        private const val DISCONNECT = "io.ashgate.android.DISCONNECT"

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
    private var tun: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == DISCONNECT) {
            worker.execute { stop(null) }
        } else {
            worker.execute { start() }
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        worker.execute { stop(null) }
    }

    override fun onDestroy() {
        worker.execute {
            close()
            set(State.OFF, error)
        }
        worker.shutdown()
        super.onDestroy()
    }

    private fun start() {
        close()
        set(State.STARTING)
        val profile = Store.selected(this) ?: return stop(getString(R.string.need_profile))
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(Mobile.Mtu.toInt())
            .addAddress("10.111.222.1", 30)
            .addAddress("fd6f:a5b9:7e11::1", 126)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            // Any address works: Xray answers port 53 itself, through the tunnel.
            .addDnsServer("1.1.1.1")
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
        if (allowed == 0) return stop(getString(R.string.need_apps))
        try {
            val fd = builder.establish() ?: return stop(getString(R.string.no_vpn_permission))
            tun = fd
            Mobile.start(profile.toString(), fd.fd.toLong(), geodata().path)
        } catch (e: Exception) {
            return stop(e.message ?: e.javaClass.simpleName)
        }
        foreground()
        set(State.ON)
    }

    private fun stop(reason: String?) {
        close()
        set(State.OFF, reason)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun close() {
        Mobile.stop()
        try {
            tun?.close()
        } catch (e: Exception) {
        }
        tun = null
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

    private fun foreground() {
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
        val notification = builder
            .setSmallIcon(R.drawable.ic_stat)
            .setContentTitle(getString(R.string.state_on))
            .setContentText(Store.selected(this)?.optString("name"))
            .setContentIntent(open)
            .setOngoing(true)
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
