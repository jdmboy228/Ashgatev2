package io.ashgate.android

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.ResolveInfo
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.util.LruCache
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.ImageView
import android.widget.ListView
import android.widget.TextView
import io.ashgate.android.TunnelService.State
import java.util.concurrent.Executors
import kotlin.concurrent.thread

/** The apps that go through the tunnel: every app with a launcher icon, with a check. */
class AppsActivity : Activity() {
    private var before: Set<String> = emptySet()

    private class App(val pkg: String, val label: String, val info: ResolveInfo)

    /** Icons are read for the rows on screen, one at a time; a few screens of them are kept. */
    private val iconLoader = Executors.newSingleThreadExecutor()
    private val icons = LruCache<String, Drawable>(64)

    companion object {
        private val labels = java.util.concurrent.ConcurrentHashMap<String, String>()

        @Volatile
        var cachedPackages: Set<String>? = null
            private set

        /** Apps with a launcher icon, without Ashgate itself. Slow: call off the main thread. */
        fun launcherApps(ctx: Context) =
            ctx.packageManager.queryIntentActivities(
                Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0,
            ).filter { it.activityInfo.packageName != ctx.packageName }.distinctBy { it.activityInfo.packageName }
                .also { list -> cachedPackages = list.mapTo(HashSet()) { it.activityInfo.packageName } }

        fun installedPackages(ctx: Context): Set<String> =
            cachedPackages ?: launcherApps(ctx).mapTo(HashSet()) { it.activityInfo.packageName }

        fun invalidateCache() {
            cachedPackages = null
        }

        fun labelOf(pm: android.content.pm.PackageManager, info: ResolveInfo): String {
            val pkg = info.activityInfo.packageName
            return labels.getOrPut(pkg) { info.activityInfo.applicationInfo.loadLabel(pm).toString() }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Reopened by the system with the Keystore failing: back to the main screen's message.
        if (!Store.usable(this)) return finish()
        setContentView(R.layout.apps)
        findViewById<View>(R.id.back).onClick { finish() }
        findViewById<TextView>(R.id.title).apply { setText(R.string.apps); typeface = Fonts.extrabold(context) }
        findViewById<TextView>(R.id.sub).apply { setText(R.string.apps_sub); typeface = Fonts.medium(context) }
        Fonts.set(Fonts.medium(this), findViewById(R.id.note))
        val list = findViewById<ListView>(R.id.list)
        before = Store.apps(this)
        val chosen = before.toMutableSet()
        // Reading the label of every app takes a moment.
        thread {
            val found = try {
                launcherApps(this)
            } catch (e: Exception) {
                emptyList<ResolveInfo>()
            }
            val apps = found
                .mapNotNull {
                    try {
                        App(it.activityInfo.packageName, labelOf(packageManager, it), it)
                    } catch (e: Exception) {
                        null // Being uninstalled right now.
                    }
                }
                // Picked apps first, then by name.
                .sortedWith(compareBy({ it.pkg !in chosen }, { it.label.lowercase() }))
            val installedPkgs = apps.mapTo(HashSet()) { it.pkg }
            runOnUiThread {
                val adapter = Adapter(apps, chosen)
                list.adapter = adapter
                // The list fades in instead of popping up once it is read.
                list.alpha = 0f
                list.animate().alpha(1f).setDuration(200).start()
                list.setOnItemClickListener { _, row, position, _ ->
                    val app = adapter.getItem(position) as? App ?: return@setOnItemClickListener
                    chosen.retainAll(installedPkgs)
                    if (!chosen.remove(app.pkg)) chosen.add(app.pkg)
                    Store.saveApps(this, chosen.toSet())
                    adapter.notifyDataSetChanged()
                    pop(row.findViewById(R.id.check))
                }
            }
        }
    }

    override fun onDestroy() {
        iconLoader.shutdownNow()
        super.onDestroy()
    }

    private fun showIcon(view: ImageView, app: App) {
        view.tag = app.pkg
        val known = icons.get(app.pkg)
        view.setImageDrawable(known)
        if (known != null || iconLoader.isShutdown) return
        iconLoader.execute {
            // The row may have scrolled away and now show another app.
            if (view.tag != app.pkg) return@execute
            val icon = try {
                app.info.activityInfo.applicationInfo.loadIcon(packageManager)
            } catch (e: Exception) {
                return@execute
            }
            runOnUiThread {
                icons.put(app.pkg, icon)
                if (view.tag == app.pkg) view.setImageDrawable(icon)
            }
        }
    }

    /** The check circle grows back from a little smaller when it flips. */
    private fun pop(check: View) {
        check.animate().cancel()
        check.scaleX = 0.75f
        check.scaleY = 0.75f
        check.animate().scaleX(1f).scaleY(1f).setDuration(200)
            .setInterpolator(android.view.animation.OvershootInterpolator(2f)).start()
    }

    override fun onPause() {
        super.onPause()
        // A running tunnel is rebuilt with the new list of apps.
        val now = Store.apps(this)
        if (now != before && TunnelService.state != State.OFF) {
            before = now
            if (now.isEmpty()) TunnelService.disconnect(this) else TunnelService.connect(this)
        }
    }

    /**
     * Picked apps, then the caption «ОСТАЛЬНЫЕ · N», then the rest. The order
     * and the caption are fixed when the screen opens, as the order was before.
     */
    private inner class Adapter(private val apps: List<App>, private val chosen: Set<String>) : BaseAdapter() {
        private val picked = apps.count { it.pkg in chosen }

        /** Where the caption goes, or -1 when nothing was picked or everything was. */
        private val caption = if (picked == 0 || picked == apps.size) -1 else picked

        override fun getCount() = apps.size + if (caption >= 0) 1 else 0

        override fun getItem(position: Int): Any? = when {
            position == caption -> null
            caption in 0 until position -> apps[position - 1]
            else -> apps[position]
        }

        override fun getItemId(position: Int) = position.toLong()

        override fun getViewTypeCount() = 2

        override fun getItemViewType(position: Int) = if (position == caption) 1 else 0

        override fun areAllItemsEnabled() = caption < 0

        override fun isEnabled(position: Int) = position != caption

        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            if (position == caption) {
                val v = (convertView ?: layoutInflater.inflate(R.layout.group_caption, parent, false)) as TextView
                v.typeface = Fonts.monoSemibold(this@AppsActivity)
                v.text = getString(R.string.apps_rest, apps.size - picked)
                return v
            }
            val v = convertView ?: layoutInflater.inflate(R.layout.app_row, parent, false)
            val app = getItem(position) as App
            val on = app.pkg in chosen
            showIcon(v.findViewById(R.id.icon), app)
            v.findViewById<TextView>(R.id.name).apply {
                text = app.label
                typeface = if (on) Fonts.semibold(this@AppsActivity) else Fonts.medium(this@AppsActivity)
                setTextColor(getColor(if (on) R.color.ag_text1 else R.color.ag_text2_strong))
            }
            v.findViewById<ImageView>(R.id.check)
                .setImageResource(if (on) R.drawable.ic_check_circle_on else R.drawable.ic_check_circle_off)
            return v
        }
    }
}
