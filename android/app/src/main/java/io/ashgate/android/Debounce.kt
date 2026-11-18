package io.ashgate.android

/**
 * Lets one action through per [windowMs]: a second tap that soon is a
 * double tap or a tap during a screen transition. No Android types, so it
 * is tested on the JVM.
 */
class Debounce(private val windowMs: Long, private val clock: () -> Long) {
    private var last: Long? = null

    @Synchronized
    fun accept(): Boolean {
        val now = clock()
        val before = last
        if (before != null && now - before < windowMs) return false
        last = now
        return true
    }
}
