package io.ashgate.android

/**
 * What the profile form makes of pasted text, and how imported servers
 * find the profiles they replace. No Android types, so it is tested on the JVM.
 */
object ProfileInput {
    enum class Kind { LINK, SUBSCRIPTION, INSECURE_SUBSCRIPTION }

    /**
     * A subscription is fetched outside the tunnel (Ashgate itself never goes
     * through it), so plain http:// would show the provider the panel's token
     * and every server with its UUID and keys. Only https:// is fetched.
     */
    fun kind(text: String): Kind {
        val t = text.trim()
        return when {
            t.startsWith("https://", ignoreCase = true) -> Kind.SUBSCRIPTION
            t.startsWith("http://", ignoreCase = true) -> Kind.INSECURE_SUBSCRIPTION
            else -> Kind.LINK
        }
    }

    /**
     * The same server in a link: user (UUID), host and port, without the
     * name and parameters that a subscription may change between imports.
     * Null for anything that is not a vless:// link.
     */
    fun serverKey(link: String): String? {
        val t = link.trim()
        if (!t.startsWith("vless://", ignoreCase = true)) return null
        val key = t.substring("vless://".length).substringBefore('#').substringBefore('?').substringBefore('/')
        return key.takeIf { it.contains('@') }?.lowercase()
    }

    /**
     * Ids for imported servers: a server that is already saved keeps its id
     * (so it is replaced, and stays selected), a new one gets null (a new id).
     * [existing] maps saved server keys to ids. [edited] is the id of the
     * profile being edited, which the first imported server takes.
     */
    fun ids(existing: Map<String, String>, incoming: List<String?>, edited: String?): List<String?> {
        val taken = mutableSetOf<String>()
        edited?.let { taken.add(it) }
        return incoming.mapIndexed { i, key ->
            if (i == 0 && edited != null) return@mapIndexed edited
            val id = key?.let { existing[it] }
            if (id != null && taken.add(id)) id else null
        }
    }
}
