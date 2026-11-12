package io.ashgate.android

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.ListView
import io.ashgate.android.TunnelService.State
import kotlin.concurrent.thread

/** The apps that go through the tunnel: every app with a launcher icon, with a checkbox. */
class AppsActivity : Activity() {
    private var before: Set<String> = emptySet()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.apps)
        val list = findViewById<ListView>(R.id.list)
        before = Store.apps(this)
        val chosen = before.toMutableSet()
        // Reading labels of every app takes a moment.
        thread {
            val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
            val apps = packageManager.queryIntentActivities(launcher, 0)
                .map { it.activityInfo.packageName to it.loadLabel(packageManager).toString() }
                .filter { it.first != packageName }
                .distinctBy { it.first }
                // Picked apps first, then by name.
                .sortedWith(compareBy({ it.first !in chosen }, { it.second.lowercase() }))
            runOnUiThread {
                list.adapter = ArrayAdapter(
                    this, android.R.layout.simple_list_item_multiple_choice, apps.map { it.second },
                )
                apps.forEachIndexed { i, app -> list.setItemChecked(i, app.first in chosen) }
                list.setOnItemClickListener { _, _, position, _ ->
                    val pkg = apps[position].first
                    if (list.isItemChecked(position)) chosen.add(pkg) else chosen.remove(pkg)
                    Store.saveApps(this, chosen.toSet())
                }
            }
        }
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
}
