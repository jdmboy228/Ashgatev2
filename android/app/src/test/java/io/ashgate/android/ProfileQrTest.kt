package io.ashgate.android

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.EncodeHintType
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.qrcode.QRCodeWriter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfileQrTest {
    private val uuid = "11111111-2222-4333-8444-555555555555"

    @Test
    fun vlessEncodeAndParseRoundTrip() {
        val link = "vless://$uuid@server.example:8443?type=xhttp&security=reality&sid=ab12#%D0%A1%D0%B5%D1%80%D0%B2%D0%B5%D1%80"
        val encoded = ProfileQr.encode("vless", link, "Ignored", "server.example", 8443, "", "")
        assertEquals(link, encoded)

        val parsed = ProfileQr.parse(encoded!!)
        assertTrue(parsed is QrPayload.VlessLink)
        assertEquals(link, (parsed as QrPayload.VlessLink).link)
    }

    @Test
    fun socks5RoundTripVariants() {
        // 1. With user + pass
        val enc1 = ProfileQr.encode("socks5", "", "Home", "192.168.1.1", 1080, "alice", "secret123")
        assertEquals("socks5://alice:secret123@192.168.1.1:1080#Home", enc1)
        val p1 = ProfileQr.parse(enc1!!)
        assertEquals(QrPayload.Proxy("socks5", "Home", "192.168.1.1", 1080, "alice", "secret123"), p1)

        // 2. With user only
        val enc2 = ProfileQr.encode("socks5", "", "Home", "192.168.1.1", 1080, "alice", "")
        assertEquals("socks5://alice@192.168.1.1:1080#Home", enc2)
        val p2 = ProfileQr.parse(enc2!!)
        assertEquals(QrPayload.Proxy("socks5", "Home", "192.168.1.1", 1080, "alice", ""), p2)

        // 3. No auth, name equals host -> no fragment
        val enc3 = ProfileQr.encode("socks5", "", "192.168.1.1", "192.168.1.1", 1080, "", "")
        assertEquals("socks5://192.168.1.1:1080", enc3)
        val p3 = ProfileQr.parse(enc3!!)
        assertEquals(QrPayload.Proxy("socks5", "192.168.1.1", "192.168.1.1", 1080, "", ""), p3)

        // 4. IPv6 [2001:db8::1]
        val enc4 = ProfileQr.encode("socks5", "", "IPv6 Server", "2001:db8::1", 1080, "", "")
        assertEquals("socks5://[2001:db8::1]:1080#IPv6%20Server", enc4)
        val p4 = ProfileQr.parse(enc4!!)
        assertEquals(QrPayload.Proxy("socks5", "IPv6 Server", "2001:db8::1", 1080, "", ""), p4)

        // 5. Special chars in password (@, :, /, %, space)
        val enc5 = ProfileQr.encode("socks5", "", "Special", "proxy.org", 1080, "my@user", "p@ss:w/o%rd ")
        assertNotNull(enc5)
        val p5 = ProfileQr.parse(enc5!!)
        assertEquals(QrPayload.Proxy("socks5", "Special", "proxy.org", 1080, "my@user", "p@ss:w/o%rd "), p5)

        // 6. Cyrillic profile name
        val enc6 = ProfileQr.encode("socks5", "", "Мой сервер", "proxy.org", 1080, "", "")
        assertNotNull(enc6)
        val p6 = ProfileQr.parse(enc6!!)
        assertEquals(QrPayload.Proxy("socks5", "Мой сервер", "proxy.org", 1080, "", ""), p6)
    }

    @Test
    fun httpProxyRoundTrip() {
        // With auth and name
        val enc1 = ProfileQr.encode("http", "", "Office", "proxy.corp", 8080, "u", "p")
        assertEquals("http://u:p@proxy.corp:8080#Office", enc1)
        val p1 = ProfileQr.parse(enc1!!)
        assertEquals(QrPayload.Proxy("http", "Office", "proxy.corp", 8080, "u", "p"), p1)

        // Without auth, IPv6
        val enc2 = ProfileQr.encode("http", "", "", "2001:db8::1", 3128, "", "")
        assertEquals("http://[2001:db8::1]:3128", enc2)
        val p2 = ProfileQr.parse(enc2!!)
        assertEquals(QrPayload.Proxy("http", "2001:db8::1", "2001:db8::1", 3128, "", ""), p2)
    }

    @Test
    fun socksBase64ShadowrocketFormat() {
        // Standard base64 of "user:pass@1.2.3.4:1080" is "dXNlcjpwYXNzQDEuMi4zLjQ6MTA4MA=="
        val uri1 = "socks://dXNlcjpwYXNzQDEuMi4zLjQ6MTA4MA==#Work"
        assertEquals(
            QrPayload.Proxy("socks5", "Work", "1.2.3.4", 1080, "user", "pass"),
            ProfileQr.parse(uri1),
        )

        // Without fragment: name defaults to host
        val uri2 = "socks://dXNlcjpwYXNzQDEuMi4zLjQ6MTA4MA=="
        assertEquals(
            QrPayload.Proxy("socks5", "1.2.3.4", "1.2.3.4", 1080, "user", "pass"),
            ProfileQr.parse(uri2),
        )

        // Paddingless
        val uri3 = "socks://dXNlcjpwYXNzQDEuMi4zLjQ6MTA4MA#Work"
        assertEquals(
            QrPayload.Proxy("socks5", "Work", "1.2.3.4", 1080, "user", "pass"),
            ProfileQr.parse(uri3),
        )

        // URL-safe characters (- and _)
        // "user?test:pass@1.2.3.4:1080" in url-safe base64
        val raw = "testuser:p+ss/word@10.0.0.1:1080"
        val standardB64 = java.util.Base64.getEncoder().encodeToString(raw.toByteArray(Charsets.UTF_8))
        val urlSafeB64 = standardB64.replace('+', '-').replace('/', '_').trimEnd('=')
        val uri4 = "socks://$urlSafeB64#Safe"
        val p4 = ProfileQr.parse(uri4)
        assertTrue(p4 is QrPayload.Proxy)
        assertEquals(1080, (p4 as QrPayload.Proxy).port)
        assertEquals("10.0.0.1", p4.host)
        assertEquals("Safe", p4.name)
    }

    @Test
    fun httpSubscriptionRejectionVsProxyAcceptance() {
        // Insecure subscriptions rejected
        assertEquals(QrPayload.InsecureSubscription, ProfileQr.parse("http://panel.example:2096/sub/token"))
        assertEquals(QrPayload.InsecureSubscription, ProfileQr.parse("http://panel.example/sub"))
        assertEquals(QrPayload.InsecureSubscription, ProfileQr.parse("http://panel.example"))
        assertEquals(QrPayload.InsecureSubscription, ProfileQr.parse("http://panel.example/"))
        assertEquals(QrPayload.InsecureSubscription, ProfileQr.parse("http://panel.example:8080?token=123"))

        // HTTP proxies accepted
        assertEquals(
            QrPayload.Proxy("http", "proxy.example", "proxy.example", 8080, "", ""),
            ProfileQr.parse("http://proxy.example:8080"),
        )
        assertEquals(
            QrPayload.Proxy("http", "Office", "proxy.example", 8080, "u", "p"),
            ProfileQr.parse("http://u:p@proxy.example:8080/#Office"),
        )
    }

    @Test
    fun httpsSubscriptionParsing() {
        assertEquals(
            QrPayload.Subscription("https://panel.example/sub/token"),
            ProfileQr.parse("https://panel.example/sub/token"),
        )
        assertEquals(
            QrPayload.Subscription("HTTPS://panel.example/sub/token"),
            ProfileQr.parse("  HTTPS://panel.example/sub/token \n"),
        )
    }

    @Test
    fun invalidInputs() {
        assertEquals(QrPayload.Invalid, ProfileQr.parse(""))
        assertEquals(QrPayload.Invalid, ProfileQr.parse("   "))
        assertEquals(QrPayload.Invalid, ProfileQr.parse("some random text"))
        assertEquals(QrPayload.Invalid, ProfileQr.parse("ftp://server.example:21/sub"))
        assertEquals(QrPayload.Invalid, ProfileQr.parse("socks5://server.example:0"))
        assertEquals(QrPayload.Invalid, ProfileQr.parse("socks5://server.example:70000"))
        assertEquals(QrPayload.Invalid, ProfileQr.parse("socks5://:1080"))
    }

    @Test
    fun proxyKeyAndProfileKeyNormalization() {
        assertEquals(
            ProfileQr.proxyKey("socks5", "example.com", 1080, "user"),
            ProfileQr.proxyKey("SOCKS5", "EXAMPLE.COM", 1080, "user"),
        )
        assertEquals(
            ProfileQr.proxyKey("socks5", "2001:db8::1", 1080, ""),
            ProfileQr.proxyKey("socks5", "[2001:DB8::1]", 1080, ""),
        )
        assertNull(ProfileQr.proxyKey("socks5", "", 1080, ""))
        assertNull(ProfileQr.proxyKey("socks5", "example.com", 0, ""))

        val vlessLink = "vless://$uuid@server.example:8443?type=xhttp&security=reality#Name"
        assertEquals("vless|$uuid@server.example:8443", ProfileQr.profileKey("vless", vlessLink, "", 0, ""))
        assertEquals("socks5|u|proxy.org:1080", ProfileQr.profileKey("socks5", "", "proxy.org", 1080, "u"))
        assertEquals("http||proxy.org:8080", ProfileQr.profileKey("http", "", "proxy.org", 8080, ""))
    }

    @Test
    fun zxingPureJvmRoundTrip() {
        val payloads = listOf(
            "vless://$uuid@server.example:8443?type=xhttp&security=reality&sid=ab12#%D0%A1%D0%B5%D1%80%D0%B2%D0%B5%D1%80",
            "socks5://user:pass@192.168.1.1:1080#%D0%9C%D0%BE%D0%B9%20%D1%81%D0%B5%D1%80%D0%B2%D0%B5%D1%80",
        )
        val writer = QRCodeWriter()
        val reader = QRCodeReader()
        val hints = mapOf(EncodeHintType.CHARACTER_SET to "UTF-8")

        for (p in payloads) {
            val matrix = writer.encode(p, BarcodeFormat.QR_CODE, 300, 300, hints)
            val w = matrix.width
            val h = matrix.height
            val pixels = IntArray(w * h)
            for (y in 0 until h) {
                for (x in 0 until w) {
                    pixels[y * w + x] = if (matrix.get(x, y)) 0xFF000000.toInt() else 0xFFFFFFFF.toInt()
                }
            }
            val source = RGBLuminanceSource(w, h, pixels)
            val result = reader.decode(BinaryBitmap(HybridBinarizer(source)))
            reader.reset()
            assertEquals(p, result.text)
        }
    }
}
