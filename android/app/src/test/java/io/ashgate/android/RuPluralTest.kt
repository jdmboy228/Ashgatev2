package io.ashgate.android

import io.ashgate.android.RuPlural.Form
import org.junit.Assert.assertEquals
import org.junit.Test

class RuPluralTest {
    @Test
    fun forms() {
        val cases = mapOf(
            0 to Form.MANY, 1 to Form.ONE, 2 to Form.FEW, 4 to Form.FEW, 5 to Form.MANY,
            11 to Form.MANY, 12 to Form.MANY, 14 to Form.MANY, 21 to Form.ONE, 22 to Form.FEW,
            25 to Form.MANY, 101 to Form.ONE, 111 to Form.MANY, 112 to Form.MANY, 1004 to Form.FEW,
        )
        for ((n, want) in cases) assertEquals("n=$n", want, RuPlural.form(n))
    }

    @Test
    fun pick() {
        val forms = arrayOf("%d приложение", "%d приложения", "%d приложений")
        assertEquals("1 приложение", RuPlural.pick(forms, 1).format(1))
        assertEquals("3 приложения", RuPlural.pick(forms, 3).format(3))
        assertEquals("0 приложений", RuPlural.pick(forms, 0).format(0))
        assertEquals("11 приложений", RuPlural.pick(forms, 11).format(11))
    }
}
