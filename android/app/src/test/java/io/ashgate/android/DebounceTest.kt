package io.ashgate.android

import org.junit.Assert.assertEquals
import org.junit.Test

class DebounceTest {
    private var now = 1_000L
    private val debounce = Debounce(500) { now }

    private fun tap(atMs: Long): Boolean {
        now = atMs
        return debounce.accept()
    }

    @Test
    fun firstTapPasses() {
        assertEquals(true, tap(1_000))
    }

    @Test
    fun doubleTapIsIgnored() {
        assertEquals(listOf(true, false, false), listOf(tap(1_000), tap(1_100), tap(1_499)))
    }

    @Test
    fun tapAfterTheWindowPasses() {
        assertEquals(listOf(true, true), listOf(tap(1_000), tap(1_500)))
    }

    @Test
    fun ignoredTapsDoNotExtendTheWindow() {
        assertEquals(listOf(true, false, true), listOf(tap(1_000), tap(1_400), tap(1_600)))
    }

    @Test
    fun clockStartingAtZeroStillLetsTheFirstTapThrough() {
        assertEquals(true, tap(0))
        assertEquals(false, tap(100))
    }
}
