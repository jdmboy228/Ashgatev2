package io.ashgate.android

/**
 * Russian plural forms. Android picks plurals by the phone's language, so on
 * an English phone the Russian UI said «5 приложения»; the rule here is
 * always Russian.
 */
object RuPlural {
    enum class Form { ONE, FEW, MANY }

    fun form(n: Int): Form {
        val a = Math.abs(n)
        val d = a % 10
        val dd = a % 100
        return when {
            d == 1 && dd != 11 -> Form.ONE
            d in 2..4 && dd !in 12..14 -> Form.FEW
            else -> Form.MANY
        }
    }

    /** [forms] is one, few, many (a string-array in that order). */
    fun pick(forms: Array<String>, n: Int): String = forms[form(n).ordinal]
}
