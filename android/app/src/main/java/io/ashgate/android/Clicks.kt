package io.ashgate.android

import android.os.SystemClock
import android.view.View

/** The last accepted tap on any button, shared so two quick taps never open two screens. */
private var lastClick = 0L

/** A click listener that ignores a second tap within 500 ms (double taps, taps during a transition). */
fun View.onClick(action: (View) -> Unit) = setOnClickListener {
    val now = SystemClock.elapsedRealtime()
    if (now - lastClick < 500) return@setOnClickListener
    lastClick = now
    action(it)
}
