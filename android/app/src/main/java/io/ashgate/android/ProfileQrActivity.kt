package io.ashgate.android

import android.app.Activity
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.widget.ImageView
import android.widget.TextView
import org.json.JSONObject
import kotlin.concurrent.thread

/** Shows one profile as a QR code another phone can scan. The code carries secrets: no screenshots. */
class ProfileQrActivity : Activity() {
    companion object {
        const val EXTRA_PROFILE_ID = "id"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // QR-код содержит UUID или пароль: скрываем из Recents и скриншотов.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(R.layout.activity_profile_qr)
        window.attributes = window.attributes.apply { screenBrightness = 0.85f }

        val title = findViewById<TextView>(R.id.title)
        val sub = findViewById<TextView>(R.id.sub)
        val hint = findViewById<TextView>(R.id.qr_hint)
        val error = findViewById<TextView>(R.id.qr_error)
        val image = findViewById<ImageView>(R.id.qr_image)
        Fonts.set(Fonts.medium(this), hint, error)
        findViewById<View>(R.id.back).onClick { finish() }

        val profileId = intent.getStringExtra(EXTRA_PROFILE_ID)
        val size = (280 * resources.displayMetrics.density).toInt().coerceIn(360, 1024).coerceAtMost(720)
        // Открытие Store (если холодный старт) и генерация QR выполняются в фоне.
        thread {
            if (!Store.usable(this)) {
                runOnUiThread { if (!isFinishing && !isDestroyed) finish() }
                return@thread
            }
            val profile = Store.find(this, profileId)
            if (profile == null) {
                runOnUiThread { if (!isFinishing && !isDestroyed) finish() }
                return@thread
            }
            val bmp = try {
                QrBitmap.encodePayload(profile)?.let { QrBitmap.generate(it, size) }
            } catch (_: Throwable) {
                null
            }
            runOnUiThread {
                if (isFinishing || isDestroyed) {
                    bmp?.recycle()
                    return@runOnUiThread
                }
                title.apply { text = profile.optString("name"); typeface = Fonts.extrabold(context) }
                sub.apply { text = meta(profile); typeface = Fonts.mono(context) }
                if (bmp == null) {
                    findViewById<View>(R.id.qr_card).visibility = View.GONE
                    hint.visibility = View.GONE
                    error.setText(R.string.qr_gen_failed)
                    error.visibility = View.VISIBLE
                } else {
                    image.setImageBitmap(bmp)
                    image.contentDescription = getString(R.string.qr_share_desc)
                }
            }
        }
    }

    /** «VLESS · XHTTP · host» or «SOCKS5 · host:port»: never the uuid or the password. */
    private fun meta(p: JSONObject): String = when (p.optString("kind")) {
        "vless" -> "VLESS · XHTTP · " + p.optString("host").ifEmpty { Uri.parse(p.optString("link")).host ?: "" }
        "socks5" -> "SOCKS5 · ${p.optString("host")}:${p.optInt("port")}"
        else -> "HTTP · ${p.optString("host")}:${p.optInt("port")}"
    }
}
