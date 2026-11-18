package io.ashgate.android

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.ImageView
import android.widget.ListView
import android.widget.TextView
import io.ashgate.android.TunnelService.State
import kotlin.concurrent.thread

/** The apps that go through the tunnel: every app with a launcher icon, with a check. */
class AppsActivity : Activity() {
    private var before: Set<String> = emptySet()

    private class App(val pkg: String, val label: String, val icon: Drawable)

    companion object {
        /** Apps with a launcher icon, without Ashgate itself. Slow: call off the main thread. */
        fun launcherApps(ctx: Context) =
            ctx.packageManager.queryIntentActivities(
                Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0,
            ).filter { it.activityInfo.packageName != ctx.packageName }.distinctBy { it.activityInfo.packageName }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.apps)
        findViewById<View>(R.id.back).onClick { finish() }
        findViewById<TextView>(R.id.title).apply { setText(R.string.apps); typeface = Fonts.extrabold(context) }
        findViewById<TextView>(R.id.sub).apply { setText(R.string.apps_sub); typeface = Fonts.medium(context) }
        val list = findViewById<ListView>(R.id.list)
        before = Store.apps(this)
        val chosen = before.toMutableSet()
        // Reading labels and icons of every app takes a moment.
        thread {
            val apps = launcherApps(this)
                .map { App(it.activityInfo.packageName, it.loadLabel(packageManager).toString(), it.loadIcon(packageManager)) }
                // Picked apps first, then by name.
                .sortedWith(compareBy({ it.pkg !in chosen }, { it.label.lowercase() }))
            runOnUiThread {
                val adapter = Adapter(apps, chosen)
                list.adapter = adapter
                // The list fades in instead of popping up once it is read.
                list.alpha = 0f
                list.animate().alpha(1f).setDuration(200).start()
                list.setOnItemClickListener { _, row, position, _ ->
                    val app = adapter.getItem(position) as? App ?: return@setOnItemClickListener
                    if (!chosen.remove(app.pkg)) chosen.add(app.pkg)
                    Store.saveApps(this, chosen.toSet())
                    adapter.notifyDataSetChanged()
                    pop(row.findViewById(R.id.check))
                }
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
            v.findViewById<ImageView>(R.id.icon).setImageDrawable(app.icon)
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
