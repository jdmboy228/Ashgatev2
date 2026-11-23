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
        val at = key.indexOf('@')
        if (at <= 0 || at == key.lastIndex) return null
        val hostPort = key.substring(at + 1)
        val hasPort = if (hostPort.startsWith('[')) {
            val close = hostPort.indexOf(']')
            close >= 0 && close + 1 < hostPort.length && hostPort[close + 1] == ':'
        } else {
            hostPort.contains(':')
        }
        val normalized = if (hasPort) key else "$key:443"
        return normalized.lowercase()
    }

    /**
     * Ids for imported servers: a server that is already saved keeps its id
     * (so it is replaced, and stays selected), a new one gets null (a new id).
     * [existing] maps saved server keys to ids, several when a subscription
     * lists one server more than once: they are used in order. [edited] is
     * the id of the profile being edited, which the first imported server takes.
     */
    fun ids(existing: Map<String, List<String>>, incoming: List<String?>, edited: String?): List<String?> {
        val free = existing.mapValues { (_, ids) -> ArrayDeque(ids.filter { it != edited }) }
        return incoming.mapIndexed { i, key ->
            if (i == 0 && edited != null) edited else key?.let { free[it]?.removeFirstOrNull() }
        }
    }

    /**
     * When editing [edited] changes its server to one that was already saved
     * under another id, returns that redundant id so the server is not saved twice.
     */
    fun duplicateOnEdit(
        existing: Map<String, List<String>>,
        incoming: List<String?>,
        assignedIds: List<String?>,
        edited: String?,
    ): String? {
        if (edited == null) return null
        val firstKey = incoming.firstOrNull() ?: return null
        val savedForFirst = existing[firstKey] ?: return null
        if (edited in savedForFirst) return null
        val used = assignedIds.filterNotNull().toSet()
        return savedForFirst.firstOrNull { it !in used }
    }
}
