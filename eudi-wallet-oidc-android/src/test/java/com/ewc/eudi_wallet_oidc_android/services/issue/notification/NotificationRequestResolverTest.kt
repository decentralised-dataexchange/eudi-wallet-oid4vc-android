package com.ewc.eudi_wallet_oidc_android.services.issue.notification

import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The notification request, section 11.
 *
 * `sendNotificationRequest` returned `Unit` and logged, so none of this was observable to a caller
 * -- an issuer refusing the notification looked exactly like one accepting it.
 */
class NotificationRequestResolverTest {

    private lateinit var server: MockWebServer

    @Before fun setUp() { server = MockWebServer(); server.start() }
    @After fun tearDown() { server.shutdown() }

    private fun session(endpoint: String? = null) = IssuanceSession(
        credentialOffer = CredentialOffer(credentialIssuer = "https://issuer.example.com"),
        issuerConfig = IssuerWellKnownConfiguration(
            credentialIssuer = "https://issuer.example.com",
            notificationEndpoint = endpoint ?: server.url("/notification").toString(),
        ),
        authConfig = null,
    )

    private fun notify(
        event: NotificationEvent = NotificationEvent.CREDENTIAL_ACCEPTED,
        notificationId: String = "n-1",
        eventDescription: String? = null,
        session: IssuanceSession = session(),
    ) = runBlocking {
        NotificationRequestResolver().resolve(
            session = session,
            token = TokenResponse(accessToken = "at-1"),
            notificationId = notificationId,
            event = event,
            eventDescription = eventDescription,
        )
    }

    @Test
    fun `a 204 is acknowledged`() {
        server.enqueue(MockResponse().setResponseCode(204))

        assertTrue(notify() is NotificationOutcome.Acknowledged)
    }

    @Test
    fun `the body names the notification and the event`() {
        server.enqueue(MockResponse().setResponseCode(204))

        notify(event = NotificationEvent.CREDENTIAL_DELETED, notificationId = "n-9")

        val body = JSONObject(server.takeRequest().body.readUtf8())
        assertEquals("n-9", body.getString("notification_id"))
        assertEquals("credential_deleted", body.getString("event"))
    }

    /** iOS could not send this event at all: its enum declared only two of the three values. */
    @Test
    fun `a storage failure can be reported`() {
        server.enqueue(MockResponse().setResponseCode(204))

        notify(event = NotificationEvent.CREDENTIAL_FAILURE, eventDescription = "keystore full")

        val body = JSONObject(server.takeRequest().body.readUtf8())
        assertEquals("credential_failure", body.getString("event"))
        assertEquals("keystore full", body.getString("event_description"))
    }

    @Test
    fun `a blank description is omitted rather than sent empty`() {
        server.enqueue(MockResponse().setResponseCode(204))

        notify(eventDescription = "  ")

        val body = JSONObject(server.takeRequest().body.readUtf8())
        assertFalse(body.has("event_description"))
    }

    @Test
    fun `a refusal carries the issuer's code and the status`() {
        server.enqueue(
            MockResponse().setResponseCode(400)
                .setBody("""{"error":"invalid_notification_id"}""")
        )

        val outcome = notify()

        assertTrue(outcome is NotificationOutcome.Failed)
        val error = (outcome as NotificationOutcome.Failed).error
        assertEquals("invalid_notification_id", error.errorCode)
        assertEquals(400, error.httpStatus)
    }

    @Test
    fun `an issuer with no notification endpoint fails rather than pretending to send`() {
        val outcome = notify(session = IssuanceSession(null, IssuerWellKnownConfiguration(), null))

        assertTrue(outcome is NotificationOutcome.Failed)
        assertTrue(
            (outcome as NotificationOutcome.Failed).error.errorDescription
                ?.contains("notification endpoint") == true
        )
    }

    @Test
    fun `a missing notification id does not reach the network`() {
        val outcome = notify(notificationId = "")

        assertTrue(outcome is NotificationOutcome.Failed)
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `every event value is the one the wire expects`() {
        assertEquals("credential_accepted", NotificationEvent.CREDENTIAL_ACCEPTED.value)
        assertEquals("credential_deleted", NotificationEvent.CREDENTIAL_DELETED.value)
        assertEquals("credential_failure", NotificationEvent.CREDENTIAL_FAILURE.value)
        assertEquals(3, NotificationEvent.entries.size)
        assertEquals(
            NotificationEvent.CREDENTIAL_FAILURE,
            NotificationEvent.fromString("credential_failure"),
        )
    }
}
