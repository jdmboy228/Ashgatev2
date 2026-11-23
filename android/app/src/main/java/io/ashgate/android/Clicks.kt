package io.ashgate.android

import android.os.SystemClock
import android.view.View

/** Shared by every button, so two quick taps never open two screens or connect twice. */
private val taps = Debounce(500) { SystemClock.elapsedRealtime() }

/** True when a tap or hold is outside the debounce window. */
fun allowTap(): Boolean = taps.accept()

/** A click listener that ignores a second tap within 500 ms. */
fun View.onClick(action: (View) -> Unit) = setOnClickListener {
    if (allowTap()) action(it)
}
