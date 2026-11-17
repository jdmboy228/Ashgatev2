package io.ashgate.android

import android.content.Context
import android.graphics.Typeface
import android.widget.TextView

/**
 * Manrope and IBM Plex Mono from assets/fonts. XML fonts need API 26 (or
 * androidx.core), and minSdk is 24, so they are loaded and set in code.
 */
object Fonts {
    private val cache = HashMap<String, Typeface>()

    @Synchronized
    private fun get(ctx: Context, file: String): Typeface =
        cache.getOrPut(file) { Typeface.createFromAsset(ctx.applicationContext.assets, "fonts/$file.ttf") }

    fun medium(ctx: Context) = get(ctx, "manrope_medium")
    fun semibold(ctx: Context) = get(ctx, "manrope_semibold")
    fun bold(ctx: Context) = get(ctx, "manrope_bold")
    fun extrabold(ctx: Context) = get(ctx, "manrope_extrabold")
    fun mono(ctx: Context) = get(ctx, "ibm_plex_mono_regular")
    fun monoSemibold(ctx: Context) = get(ctx, "ibm_plex_mono_semibold")

    /** Sets [font] on every view. */
    fun set(font: Typeface, vararg views: TextView) = views.forEach { it.typeface = font }
}
