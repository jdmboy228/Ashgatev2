package io.ashgate.android

import io.ashgate.android.ProfileInput.Kind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

// Fake servers only: documentation addresses and made-up ids.
class ProfileInputTest {
    private val uuid = "11111111-2222-4333-8444-555555555555"
    private val link = "vless://$uuid@server.example:8443?type=xhttp&security=reality&sid=ab12#Sweden"

    @Test
    fun plainHttpSubscriptionIsRefused() {
        assertEquals(Kind.INSECURE_SUBSCRIPTION, ProfileInput.kind("http://panel.example:2096/sub/token"))
        assertEquals(Kind.INSECURE_SUBSCRIPTION, ProfileInput.kind("  HTTP://panel.example/sub/token\n"))
    }

    @Test
    fun httpsSubscriptionIsFetched() {
        assertEquals(Kind.SUBSCRIPTION, ProfileInput.kind("https://panel.example/sub/token"))
        assertEquals(Kind.SUBSCRIPTION, ProfileInput.kind(" HTTPS://panel.example/sub/token "))
    }

    @Test
    fun anythingElseIsALink() {
        assertEquals(Kind.LINK, ProfileInput.kind(link))
        assertEquals(Kind.LINK, ProfileInput.kind("httpx://nope"))
        assertEquals(Kind.LINK, ProfileInput.kind(""))
    }

    @Test
    fun serverKeyIgnoresNameAndParameters() {
        val renamed = "vless://$uuid@server.example:8443?type=xhttp&security=reality&sid=cd34&path=%2Fnew#Other"
        assertEquals("$uuid@server.example:8443", ProfileInput.serverKey(link))
        assertEquals(ProfileInput.serverKey(link), ProfileInput.serverKey(renamed))
        assertEquals(ProfileInput.serverKey(link), ProfileInput.serverKey(" VLESS://${uuid.uppercase()}@SERVER.example:8443/?x=1"))
    }

    @Test
    fun differentServersHaveDifferentKeys() {
        val otherPort = link.replace(":8443", ":443")
        val otherUser = link.replace("5555-", "6666-").replace("555555555555", "666666666666")
        assertEquals(3, setOf(ProfileInput.serverKey(link), ProfileInput.serverKey(otherPort), ProfileInput.serverKey(otherUser)).size)
    }

    @Test
    fun notALinkHasNoKey() {
        assertNull(ProfileInput.serverKey(""))
        assertNull(ProfileInput.serverKey("https://panel.example/sub"))
        assertNull(ProfileInput.serverKey("vless://no-user-part"))
    }

    @Test
    fun reimportReusesIds() {
        val saved = mapOf("a@one:443" to "id-1", "b@two:443" to "id-2")
        // The same subscription again, with one new server: nothing is added twice.
        assertEquals(
            listOf("id-1", null, "id-2"),
            ProfileInput.ids(saved, listOf("a@one:443", "c@three:443", "b@two:443"), null),
        )
    }

    @Test
    fun aServerListedTwiceGetsOneId() {
        val saved = mapOf("a@one:443" to "id-1")
        assertEquals(listOf("id-1", null), ProfileInput.ids(saved, listOf("a@one:443", "a@one:443"), null))
    }

    @Test
    fun editedProfileKeepsItsId() {
        val saved = mapOf("a@one:443" to "id-1", "b@two:443" to "id-2")
        assertEquals(
            listOf("id-9", "id-2"),
            ProfileInput.ids(saved, listOf("x@new:443", "b@two:443"), "id-9"),
        )
        // The edited id is never given to a second server.
        assertEquals(listOf("id-1", null), ProfileInput.ids(saved, listOf("a@one:443", null), "id-1"))
    }

    @Test
    fun proxiesWithoutKeysAreNew() {
        assertEquals(listOf(null), ProfileInput.ids(mapOf("a@one:443" to "id-1"), listOf(null), null))
    }
}
