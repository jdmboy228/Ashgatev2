package io.ashgate.android

import java.io.ByteArrayOutputStream

sealed class QrPayload {
    data class VlessLink(val link: String) : QrPayload()
    data class Subscription(val url: String) : QrPayload()
    data class Proxy(
        val kind: String,
        val name: String,
        val host: String,
        val port: Int,
        val user: String,
        val pass: String,
    ) : QrPayload()
    object InsecureSubscription : QrPayload()
    object Invalid : QrPayload()
}

/**
 * Pure Kotlin QR payload encoder and parser.
 * ZERO android.* and ZERO org.json.* imports so it runs in JVM unit tests without stubs.
 */
object ProfileQr {
    typealias QrPayload = io.ashgate.android.QrPayload

    fun encode(
        kind: String,
        link: String,
        name: String,
        host: String,
        port: Int,
        user: String,
        pass: String,
    ): String? {
        if (kind.equals("vless", ignoreCase = true)) {
            return link.trim().takeIf { it.isNotEmpty() }
        }
        if (!kind.equals("socks5", ignoreCase = true) && !kind.equals("http", ignoreCase = true)) {
            return null
        }
        val h = host.trim()
        if (h.isEmpty() || port !in 1..65535) return null
        val scheme = kind.lowercase()
        val hostPart = if (h.contains(':') && (!h.startsWith('[') || !h.endsWith(']'))) "[$h]" else h
        val auth = if (user.isNotEmpty()) {
            val u = percentEncode(user)
            val p = if (pass.isNotEmpty()) ":${percentEncode(pass)}" else ""
            "$u$p@"
        } else {
            ""
        }
        val trimmedName = name.trim()
        val unbracketedHost = h.trimStart('[').trimEnd(']')
        val unbracketedName = trimmedName.trimStart('[').trimEnd(']')
        val fragment = if (trimmedName.isNotEmpty() && trimmedName != h && unbracketedName != unbracketedHost) {
            "#${percentEncode(trimmedName)}"
        } else {
            ""
        }
        return "$scheme://$auth$hostPart:$port$fragment"
    }

    fun parse(raw: String): QrPayload {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return QrPayload.Invalid
        val lower = trimmed.lowercase()
        return when {
            lower.startsWith("vless://") -> QrPayload.VlessLink(trimmed)
            lower.startsWith("https://") -> QrPayload.Subscription(trimmed)
            lower.startsWith("socks5://") || lower.startsWith("socks://") -> parseSocks(trimmed)
            lower.startsWith("http://") -> parseHttp(trimmed)
            else -> QrPayload.Invalid
        }
    }

    private fun parseSocks(trimmed: String): QrPayload {
        val colonSlashSlash = trimmed.indexOf("://")
        if (colonSlashSlash < 0) return QrPayload.Invalid
        val withoutScheme = trimmed.substring(colonSlashSlash + 3)
        val fragmentPart = if (withoutScheme.contains('#')) withoutScheme.substringAfter('#') else ""
        val mainPart = withoutScheme.substringBefore('#').trimEnd('/')

        val standard = parseAuthority(mainPart, fragmentPart, "socks5")
        if (standard !is QrPayload.Invalid) {
            return standard
        }

        // Try v2rayNG / Shadowrocket base64 format: socks://<base64(user:pass@host:port)>#name
        val decodedBytes = decodeBase64(mainPart)
        if (decodedBytes != null && decodedBytes.isNotEmpty()) {
            val decodedStr = decodedBytes.toString(Charsets.UTF_8).trim()
            val innerFrag = if (fragmentPart.isNotBlank()) {
                fragmentPart
            } else if (decodedStr.contains('#')) {
                decodedStr.substringAfter('#')
            } else {
                ""
            }
            val innerAuth = decodedStr.substringBefore('#').trimEnd('/')
            val fromBase64 = parseAuthority(innerAuth, innerFrag, "socks5")
            if (fromBase64 !is QrPayload.Invalid) {
                return fromBase64
            }
        }
        return QrPayload.Invalid
    }

    private fun parseHttp(trimmed: String): QrPayload {
        val afterScheme = trimmed.substring("http://".length)
        val fragmentPart = if (afterScheme.contains('#')) afterScheme.substringAfter('#') else ""
        val beforeFragment = afterScheme.substringBefore('#')

        if (beforeFragment.contains('?')) {
            return QrPayload.InsecureSubscription
        }
        val slashIndex = beforeFragment.indexOf('/')
        val path = if (slashIndex >= 0) beforeFragment.substring(slashIndex) else ""
        if (path.isNotEmpty() && path != "/") {
            return QrPayload.InsecureSubscription
        }
        val authority = if (slashIndex >= 0) beforeFragment.substring(0, slashIndex) else beforeFragment
        if (authority.isEmpty()) {
            return QrPayload.InsecureSubscription
        }

        // Must have an explicit numeric port in 1..65535
        val parsed = parseAuthority(authority, fragmentPart, "http")
        return if (parsed is QrPayload.Proxy) parsed else QrPayload.InsecureSubscription
    }

    private fun parseAuthority(authority: String, fragment: String, kind: String): QrPayload {
        if (authority.isEmpty()) return QrPayload.Invalid
        val userpass: String
        val hostport: String
        if (authority.contains('@')) {
            userpass = authority.substringBeforeLast('@')
            hostport = authority.substringAfterLast('@')
        } else {
            userpass = ""
            hostport = authority
        }

        val rawUser = if (userpass.contains(':')) userpass.substringBefore(':') else userpass
        val rawPass = if (userpass.contains(':')) userpass.substringAfter(':') else ""
        val user = percentDecode(rawUser)
        val pass = percentDecode(rawPass)

        val host: String
        val port: Int
        if (hostport.startsWith('[')) {
            val close = hostport.indexOf(']')
            if (close < 0) return QrPayload.Invalid
            host = hostport.substring(1, close)
            val rest = hostport.substring(close + 1)
            if (!rest.startsWith(':')) return QrPayload.Invalid
            port = rest.substring(1).toIntOrNull() ?: return QrPayload.Invalid
        } else {
            val colon = hostport.lastIndexOf(':')
            if (colon < 0) return QrPayload.Invalid
            host = hostport.substring(0, colon)
            port = hostport.substring(colon + 1).toIntOrNull() ?: return QrPayload.Invalid
        }

        if (host.isEmpty() || port !in 1..65535) return QrPayload.Invalid
        val name = if (fragment.isNotBlank()) percentDecode(fragment.trim()) else host
        return QrPayload.Proxy(kind, name, host, port, user, pass)
    }

    fun proxyKey(kind: String, host: String, port: Int, user: String): String? {
        if (!kind.equals("socks5", ignoreCase = true) && !kind.equals("http", ignoreCase = true)) return null
        val h = host.trim().trimStart('[').trimEnd(']')
        if (h.isEmpty() || port !in 1..65535) return null
        return "${kind.lowercase()}|$user|${h.lowercase()}:$port"
    }

    fun profileKey(kind: String, link: String, host: String, port: Int, user: String): String? {
        return if (kind.equals("vless", ignoreCase = true)) {
            ProfileInput.serverKey(link)?.let { "vless|$it" }
        } else {
            proxyKey(kind, host, port, user)
        }
    }

    internal fun percentEncode(s: String): String {
        val bytes = s.toByteArray(Charsets.UTF_8)
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val c = b.toInt().toChar()
            if (c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '-' || c == '_' || c == '.' || c == '~') {
                sb.append(c)
            } else {
                sb.append('%')
                val hex = (b.toInt() and 0xFF).toString(16).uppercase()
                if (hex.length == 1) sb.append('0')
                sb.append(hex)
            }
        }
        return sb.toString()
    }

    internal fun percentDecode(s: String): String {
        if (!s.contains('%')) return s
        val bytes = ByteArrayOutputStream()
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '%' && i + 2 < s.length) {
                val hex = s.substring(i + 1, i + 3)
                val byteVal = hex.toIntOrNull(16)
                if (byteVal != null) {
                    bytes.write(byteVal)
                    i += 3
                    continue
                }
            }
            val charBytes = c.toString().toByteArray(Charsets.UTF_8)
            bytes.write(charBytes, 0, charBytes.size)
            i++
        }
        return bytes.toByteArray().toString(Charsets.UTF_8)
    }

    internal fun decodeBase64(input: String): ByteArray? {
        val clean = input.trim()
        if (clean.isEmpty()) return ByteArray(0)
        val sb = StringBuilder()
        for (ch in clean) {
            if (ch == '=') break
            if (ch.isWhitespace()) continue
            sb.append(ch)
        }
        val len = sb.length
        if (len % 4 == 1) return null
        val pad = when (len % 4) {
            2 -> 2
            3 -> 1
            else -> 0
        }
        for (i in 0 until pad) {
            sb.append('=')
        }
        val totalLen = sb.length
        val out = ByteArrayOutputStream(totalLen * 3 / 4)
        var i = 0
        while (i < totalLen) {
            val c0 = charToBits(sb[i])
            val c1 = charToBits(sb[i + 1])
            val isPad2 = sb[i + 2] == '='
            val isPad3 = sb[i + 3] == '='
            val c2 = if (isPad2) -1 else charToBits(sb[i + 2])
            val c3 = if (isPad3) -1 else charToBits(sb[i + 3])
            if (c0 < 0 || c1 < 0 || (!isPad2 && c2 < 0) || (!isPad3 && c3 < 0)) return null
            if (isPad2 && !isPad3) return null
            val b0 = (c0 shl 2) or (c1 shr 4)
            out.write(b0)
            if (c2 >= 0) {
                val b1 = ((c1 and 0xF) shl 4) or (c2 shr 2)
                out.write(b1)
                if (c3 >= 0) {
                    val b2 = ((c2 and 0x3) shl 6) or c3
                    out.write(b2)
                }
            }
            i += 4
        }
        return out.toByteArray()
    }

    private fun charToBits(c: Char): Int = when (c) {
        in 'A'..'Z' -> c - 'A'
        in 'a'..'z' -> c - 'a' + 26
        in '0'..'9' -> c - '0' + 52
        '+', '-' -> 62
        '/', '_' -> 63
        else -> -1
    }
}
