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
import android.net.NetworkCapabilities
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
import java.util.concurrent.atomic.AtomicInteger

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

        /** Интервал проверки работающего туннеля (оптимизируется на Этапе 2). */
        private const val HEALTH_INTERVAL_MS = 15_000L

        /** Экспоненциальные задержки автоповтора в состоянии BLOCKED. */
        private val BLOCKED_RETRY_MS = longArrayOf(15_000L, 30_000L, 60_000L, 120_000L)

        /**
         * Один поток на все экземпляры сервиса (Go-ядро одно на процесс):
         * подключения и отключения не пересекаются, даже при смене инстанса.
         */
        private val worker = Executors.newSingleThreadScheduledExecutor()

        /** Отдельный поток для немедленного Mobile.stop() без блокировки UI-потока. */
        private val aborter = Executors.newSingleThreadExecutor()

        private fun abortCore() {
            aborter.execute {
                try {
                    Mobile.stop()
                } catch (e: Throwable) {
                    Log.e("Ashgate", "abort core failed: " + e.javaClass.name)
                }
            }
        }

        /** Логируем только класс исключения: текст ошибки может содержать адрес сервера. */
        private fun onWorker(block: () -> Unit) {
            worker.execute {
                try {
                    block()
                } catch (e: Throwable) {
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

        @Volatile
        private var geoDir: File? = null

        /** Атомарный счётчик команд, чтобы устаревшие запуски и проверки отбрасывались. */
        private val commandSeq = AtomicInteger(0)

        /** The current active service instance; an older instance being destroyed must not touch global state. */
        @Volatile
        private var active: TunnelService? = null

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
    private var healthCheck: ScheduledFuture<*>? = null
    private var blockedRetry: ScheduledFuture<*>? = null
    private var blockedAttempt = 0

    /** Выставляется ТОЛЬКО в onDestroy(): запланированные задачи этого инстанса больше не выполняются. */
    private var destroyed = false

    /** The newest start request processed on [worker], so that stopping never drops one that just came. */
    private var lastStartId = 0

    /** True once the system started or restarted the tunnel without the user on screen, so a failure notifies. */
    private var expectedUp = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val disconnect = intent?.action == DISCONNECT
        val systemStart = intent == null || intent.action == SERVICE_INTERFACE
        active = this
        // Системный bind/start VpnService во время уже идущего старта или работы не должен сбрасывать туннель.
        if (systemStart && (state == State.STARTING || state == State.ON)) {
            onWorker {
                lastStartId = startId
                expectedUp = true
            }
            return START_STICKY
        }
        val seq = commandSeq.incrementAndGet()
        if (disconnect || state == State.STARTING) {
            // Прерываем возможный блокирующий Mobile.start на отдельном потоке, не вешая UI.
            abortCore()
        }
        onWorker {
            lastStartId = startId
            if (destroyed || active !== this) return@onWorker
            if (systemStart) expectedUp = true
            when {
                disconnect -> stop(null, seq)
                else -> {
                    blockedAttempt = 0
                    cancelBlockedRetry()
                    cancelRestart()
                    start(seq)
                }
            }
        }
        return START_STICKY
    }

    override fun onRevoke() {
        // Система уже забрала VPN-интерфейс: немедленно прерываем идущий Mobile.start/check.
        val seq = commandSeq.incrementAndGet()
        abortCore()
        later { stop(getString(R.string.vpn_revoked), seq) }
    }

    /** Runs on [worker]; a callback that arrives after onDestroy is dropped. */
    private fun later(block: () -> Unit) {
        onWorker { if (!destroyed && active === this) block() }
    }

    override fun onDestroy() {
        val isCurrent = active === this
        if (isCurrent) {
            commandSeq.incrementAndGet()
            abortCore()
        }
        onWorker {
            val shouldStopCore = !destroyed && (active === this || tun != null)
            destroyed = true
            if (active === this) active = null
            cancelRestart()
            cancelHealthCheck()
            cancelBlockedRetry()
            unwatch()
            close(stopCore = shouldStopCore)
            if (shouldStopCore) set(State.OFF, error)
        }
        super.onDestroy()
    }

    /** Объединяет серию сетевых событий в пределах [RESTART_DELAY_MS] в один перезапуск. */
    private fun restartSoon(full: Boolean) {
        restartFull = restartFull || full
        if (restart != null) return
        val seq = commandSeq.get()
        restart = worker.schedule(
            Runnable {
                restart = null
                val rebuild = restartFull || tun == null
                restartFull = false
                if (destroyed || active !== this || seq != commandSeq.get() || state == State.OFF || state == State.STARTING) {
                    return@Runnable
                }
                if (rebuild) start(seq) else guarded { restartXray(seq) }
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
     * Поднимает туннель или переводит работающий на текущий профиль и список приложений.
     * Новый интерфейс создаётся до закрытия старого, чтобы трафик приложений не утёк.
     */
    private fun start(seq: Int) {
        guarded { bringUp(seq) }
    }

    private fun bringUp(seq: Int) {
        if (destroyed || active !== this || seq != commandSeq.get()) return
        cancelBlockedRetry()
        set(State.STARTING)
        // Переводим сервис в foreground сразу, не дожидаясь Mobile.start (Verify может занять до ~19 с).
        foreground(NoteMode.STARTING)
        val profile = Store.selected(this) ?: return fail(getString(R.string.need_profile))
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(Mobile.Mtu.toInt())
            .addAddress("10.111.222.1", 30)
            .addAddress("fd6f:a5b9:7e11::1", 126)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            // Любой адрес: Xray перехватывает порт 53 сам через туннель.
            .addDnsServer("1.1.1.1")
        // false = наследовать meteredness реальной сети.
        if (Build.VERSION.SDK_INT >= 29) builder.setMetered(false)
        var allowed = 0
        for (pkg in Store.apps(this)) {
            if (pkg == packageName) continue
            try {
                builder.addAllowedApplication(pkg)
                allowed++
            } catch (e: PackageManager.NameNotFoundException) {
                // Приложение уже удалено.
            }
        }
        // Без списка разрешённых приложений VPN захватил бы всё, включая сам Ashgate.
        if (allowed == 0) return fail(getString(R.string.need_apps))
        if (destroyed || active !== this || seq != commandSeq.get()) return
        var fd: ParcelFileDescriptor? = null
        try {
            fd = builder.establish()
        } catch (e: Exception) {
            return fail(e.message ?: e.javaClass.simpleName)
        }
        // null: разрешение на VPN отозвано, и старый интерфейс уже снят.
        if (fd == null) return stop(getString(R.string.no_vpn_permission), seq)
        if (destroyed || active !== this || seq != commandSeq.get()) {
            closeQuietly(fd)
            return
        }
        val old = tun
        tun = fd
        closeQuietly(old)
        runXray(profile, fd, seq)
    }

    /** Перезапускает Xray на уже поднятом TUN-интерфейсе без утечки трафика. */
    private fun restartXray(seq: Int) {
        if (destroyed || active !== this || seq != commandSeq.get()) return
        val fd = tun ?: return
        cancelBlockedRetry()
        set(State.STARTING)
        foreground(NoteMode.STARTING)
        val profile = Store.selected(this) ?: return fail(getString(R.string.need_profile))
        runXray(profile, fd, seq)
    }

    private fun runXray(profile: JSONObject, fd: ParcelFileDescriptor, seq: Int) {
        if (destroyed || active !== this || seq != commandSeq.get()) return
        cancelHealthCheck()
        try {
            // Останавливает предыдущий Xray (если есть), запускает новый на этом fd
            // и проверяет стабильность соединения через прокси-сервер.
            Mobile.start(profile.toString(), fd.fd.toLong(), geodata().path)
        } catch (e: Throwable) {
            if (destroyed || active !== this || seq != commandSeq.get()) return
            return fail(e.message ?: e.javaClass.simpleName)
        }
        if (destroyed || active !== this || seq != commandSeq.get()) {
            Mobile.stop()
            return
        }
        blockedAttempt = 0
        cancelBlockedRetry()
        watch()
        foreground(NoteMode.ON, profile.optString("name"))
        set(State.ON)
        scheduleHealthCheck(seq)
    }

    private fun scheduleHealthCheck(seq: Int) {
        cancelHealthCheck()
        healthCheck = worker.schedule(
            Runnable {
                healthCheck = null
                if (destroyed || active !== this || seq != commandSeq.get() || state != State.ON) return@Runnable
                try {
                    Mobile.check()
                } catch (e: Throwable) {
                    if (destroyed || active !== this || seq != commandSeq.get() || state != State.ON) return@Runnable
                    fail(e.message ?: e.javaClass.simpleName)
                    return@Runnable
                }
                if (!destroyed && active === this && seq == commandSeq.get() && state == State.ON) {
                    scheduleHealthCheck(seq)
                }
            },
            HEALTH_INTERVAL_MS,
            TimeUnit.MILLISECONDS,
        )
    }

    private fun cancelHealthCheck() {
        healthCheck?.cancel(false)
        healthCheck = null
    }

    /** Планирует автоповтор подключения из состояния BLOCKED с экспоненциальным backoff. */
    private fun scheduleBlockedRetry(seq: Int) {
        cancelBlockedRetry()
        val idx = blockedAttempt.coerceAtMost(BLOCKED_RETRY_MS.lastIndex)
        val delayMs = BLOCKED_RETRY_MS[idx]
        blockedAttempt++
        blockedRetry = worker.schedule(
            Runnable {
                blockedRetry = null
                if (destroyed || active !== this || seq != commandSeq.get() || state != State.BLOCKED || tun == null) {
                    return@Runnable
                }
                guarded { restartXray(seq) }
            },
            delayMs,
            TimeUnit.MILLISECONDS,
        )
    }

    private fun cancelBlockedRetry() {
        blockedRetry?.cancel(false)
        blockedRetry = null
    }

    /**
     * Неудачный запуск или разрыв. Если TUN-интерфейс уже поднят, он остаётся без Xray
     * (fail-closed: выбранные приложения без сети, утечки нет), но планируется автоповтор.
     */
    private fun fail(reason: String) {
        cancelHealthCheck()
        val seq = commandSeq.get()
        if (tun == null) return stop(reason, seq)
        Mobile.stop()
        // Сначала обновляем состояние, чтобы UI показал причину независимо от дальнейших шагов.
        set(State.BLOCKED, reason)
        watch()
        foreground(NoteMode.BLOCKED)
        scheduleBlockedRetry(seq)
    }

    private fun stop(reason: String?, seq: Int) {
        val wasUp = tun != null || expectedUp
        expectedUp = false
        blockedAttempt = 0
        cancelRestart()
        cancelHealthCheck()
        cancelBlockedRetry()
        unwatch()
        close(stopCore = true)
        // Не трогаем глобальное состояние и не вызываем stopSelf, если в очереди уже есть более новая команда.
        if (seq != commandSeq.get()) return
        if (active === this) active = null
        set(State.OFF, reason)
        stopForeground(STOP_FOREGROUND_REMOVE)
        if (reason != null && wasUp) notifyDown()
        stopSelf(lastStartId)
    }

    private fun close(stopCore: Boolean) {
        if (stopCore) Mobile.stop()
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
            private var seeded = false

            override fun onAvailable(n: Network) {
                val caps = try {
                    manager.getNetworkCapabilities(n)
                } catch (e: Exception) {
                    null
                }
                // Ignore our own VPN interface: only physical network switches count.
                if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return
                later {
                    if (watching !== this) return@later
                    val previous = network
                    network = n
                    if (!seeded) {
                        // The first delivery on registration reports the current network, which is no change.
                        seeded = true
                        return@later
                    }
                    if (previous != n && state != State.OFF) {
                        blockedAttempt = 0
                        restartSoon(full = false)
                    }
                }
            }

            override fun onCapabilitiesChanged(n: Network, caps: NetworkCapabilities) {
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) return
                later {
                    if (watching !== this) return@later
                    if (state == State.BLOCKED) {
                        blockedAttempt = 0
                        restartSoon(full = false)
                    }
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

    private fun watchInstalls() {
        if (installs != null) return
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                AppsActivity.invalidateCache()
                // An update keeps the uid.
                if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
                val pkg = intent.data?.schemeSpecificPart ?: return
                later {
                    if (tun != null && pkg in Store.apps(this@TunnelService)) {
                        cancelRestart()
                        start(commandSeq.get())
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
        geoDir?.let { return it }
        val dir = File(filesDir, "geo")
        val stamp = File(dir, "stamp")
        val build = packageManager.getPackageInfo(packageName, 0).lastUpdateTime.toString()
        if (stamp.exists() && stamp.readText() == build) {
            geoDir = dir
            return dir
        }
        dir.mkdirs()
        for (name in listOf("geosite.dat")) {
            assets.open(name).use { input ->
                File(dir, name).outputStream().use { input.copyTo(it) }
            }
        }
        stamp.writeText(build)
        geoDir = dir
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

    private enum class NoteMode { STARTING, ON, BLOCKED }

    private fun foreground(mode: NoteMode, profileName: String? = null) {
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
        when (mode) {
            NoteMode.BLOCKED -> {
                val retry = PendingIntent.getService(
                    this, 2, Intent(this, TunnelService::class.java).setAction(RETRY), flags,
                )
                builder.setContentTitle(getString(R.string.state_blocked))
                    .setContentText(getString(R.string.blocked_note))
                    .addAction(Notification.Action.Builder(null, getString(R.string.retry), retry).build())
            }
            NoteMode.STARTING -> {
                builder.setContentTitle(getString(R.string.state_starting))
                    .setContentText(profileName?.takeIf { it.isNotEmpty() } ?: getString(R.string.title_starting))
            }
            NoteMode.ON -> {
                val name = profileName?.takeIf { it.isNotEmpty() }
                    ?: try { Store.selected(this)?.optString("name") } catch (_: Exception) { null }
                builder.setContentTitle(getString(R.string.state_on))
                    .setContentText(name)
            }
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
            // Логируем только класс исключения (без сообщений); активный VpnService продолжает работу.
            Log.w("Ashgate", "startForeground failed: " + e.javaClass.name)
        }
    }
}
