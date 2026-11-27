package io.ashgate.android

import android.os.SystemClock
import android.view.View

/** Общий дебаунс на 350 мс: исключает двойное открытие экранов/подключений без «залипания» переходов. */
private val taps = Debounce(350) { SystemClock.elapsedRealtime() }

/** True when a tap or hold is outside the debounce window. */
fun allowTap(): Boolean = taps.accept()

/** A click listener that ignores a second tap within 500 ms. */
fun View.onClick(action: (View) -> Unit) = setOnClickListener {
    if (allowTap()) action(it)
}
