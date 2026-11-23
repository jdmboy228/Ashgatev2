package io.ashgate.android

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.ListView
import android.widget.TextView
import io.ashgate.android.TunnelService.State
import org.json.JSONObject

/** The profile list, opened from the «Профиль» row: pick, hold to edit, add. */
class ProfilesActivity : Activity() {
    private lateinit var list: ListView
    private var profiles: List<JSONObject> = emptyList()

    /** Read once per refresh: every read decrypts, and each row needs it. */
    private var selectedId: String? = null
    private val adapter = Adapter()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Reopened by the system with the Keystore failing: back to the main screen's message.
        if (!Store.usable(this)) return finish()
        setContentView(R.layout.profiles)
        findViewById<View>(R.id.back).onClick { finish() }
        findViewById<TextView>(R.id.title).apply { setText(R.string.profiles); typeface = Fonts.extrabold(context) }
        findViewById<TextView>(R.id.sub).apply { setText(R.string.profiles_sub); typeface = Fonts.medium(context) }
        Fonts.set(Fonts.medium(this), findViewById(R.id.empty))
        Fonts.set(Fonts.extrabold(this), findViewById(R.id.add_text))

        list = findViewById(R.id.list)
        list.emptyView = findViewById(R.id.empty)
        list.adapter = adapter
        list.setOnItemClickListener { _, row, position, _ ->
            val id = profiles[position].getString("id")
            if (id == selectedId) return@setOnItemClickListener
            Store.select(this, id)
            selectedId = id
            adapter.notifyDataSetChanged()
            // The check fades in on the picked profile.
            row.findViewById<View>(R.id.check).apply {
                animate().cancel()
                alpha = 0f
                animate().alpha(1f).setDuration(200).start()
            }
            // A running tunnel moves to the new profile.
            if (TunnelService.state != State.OFF) TunnelService.connect(this)
        }
        list.setOnItemLongClickListener { _, _, position, _ ->
            // A tap on «Назад» or «Добавить» right before would open two screens.
            if (allowTap()) {
                startActivity(
                    Intent(this, ProfileActivity::class.java).putExtra("id", profiles[position].getString("id")),
                )
            }
            true
        }
        findViewById<View>(R.id.add).onClick {
            startActivity(Intent(this, ProfileActivity::class.java))
        }
    }

    override fun onResume() {
        super.onResume()
        // After adding, editing or deleting a profile.
        profiles = Store.profiles(this)
        selectedId = Store.selectedId(this)
        adapter.notifyDataSetChanged()
    }

    /** «VLESS · XHTTP · host» or «SOCKS5 · host:port»: never the uuid or the password. */
    private fun meta(p: JSONObject): String = when (p.optString("kind")) {
        "vless" -> "VLESS · XHTTP · " + (Uri.parse(p.optString("link")).host ?: "")
        "socks5" -> "SOCKS5 · ${p.optString("host")}:${p.optInt("port")}"
        else -> "HTTP · ${p.optString("host")}:${p.optInt("port")}"
    }

    private inner class Adapter : BaseAdapter() {
        override fun getCount() = profiles.size

        override fun getItem(position: Int) = profiles[position]

        override fun getItemId(position: Int) = position.toLong()

        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val v = convertView ?: layoutInflater.inflate(R.layout.profile_row, parent, false)
            val p = profiles[position]
            val selected = p.getString("id") == selectedId
            // Hairlines only between rows.
            v.findViewById<View>(R.id.divider).visibility = if (position == 0) View.GONE else View.VISIBLE
            v.findViewById<TextView>(R.id.name).apply {
                text = p.optString("name")
                typeface = if (selected) Fonts.bold(context) else Fonts.medium(context)
                setTextColor(getColor(if (selected) R.color.ag_text1 else R.color.ag_text2_strong))
            }
            v.findViewById<TextView>(R.id.meta).apply {
                text = meta(p)
                typeface = Fonts.mono(context)
            }
            v.findViewById<View>(R.id.check).visibility = if (selected) View.VISIBLE else View.INVISIBLE
            return v
        }
    }
}
