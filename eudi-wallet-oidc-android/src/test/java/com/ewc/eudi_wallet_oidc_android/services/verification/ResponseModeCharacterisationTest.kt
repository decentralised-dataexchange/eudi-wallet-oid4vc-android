package com.ewc.eudi_wallet_oidc_android.services.verification

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.CLIENT_ID
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.DID
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.NONCE
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.dcqlRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.dcqlSdJwt
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.encryptionMetadata
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.json
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.key
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.keyBindingJwt
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.sdJwt
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.verifierEncryptionKey
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse.AuthorisationResponseHandler
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.util.Base64URL
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Characterisation of how each `response_mode` shapes the parameter map today. See
 * [PexResponseCharacterisationTest] for the purpose of these tests.
 */
class ResponseModeCharacterisationTest {

    private val holder = key()
    private val verifierKey = verifierEncryptionKey()

    private fun respond(request: PresentationRequest): Map<String, String> = runBlocking {
        AuthorisationResponseHandler().prepareAuthorisationResponseV2(
            presentationRequest = request,
            credentialList = listOf(listOf(sdJwt())),
            did = DID,
            jwk = holder,
            jwkList = listOf(listOf(holder)),
        )
    }

    private fun decrypt(jwe: String): JWEObject =
        JWEObject.parse(jwe).apply { decrypt(ECDHDecrypter(verifierKey)) }

    @Test
    fun `direct_post dot jwt encrypts the response with the enc the verifier names`() {
        val request = dcqlRequest(
            dcqlSdJwt("pid"),
            responseMode = "direct_post.jwt",
            clientMetadata = encryptionMetadata(verifierKey, enc = "A128GCM"),
        )
        val params = respond(request)

        assertEquals(setOf("response"), params.keys)
        val jwe = decrypt(params.getValue("response"))
        assertEquals(JWEAlgorithm.ECDH_ES, jwe.header.algorithm)
        assertEquals(EncryptionMethod.A128GCM, jwe.header.encryptionMethod)
        assertEquals("verifier-enc", jwe.header.keyID)
        assertEquals(Base64URL.encode(NONCE), jwe.header.agreementPartyVInfo)
        assertEquals(Base64URL.encode(CLIENT_ID), jwe.header.agreementPartyUInfo)
        val payload = jwe.payload.toJSONObject()
        assertTrue(payload.containsKey("vp_token"))
        assertTrue(payload.containsKey("state"))
    }

    @Test
    fun `direct_post dot jwt prefers A128CBC-HS256 when the verifier lists several`() {
        val metadata = encryptionMetadata(verifierKey, enc = null).toMutableMap().apply {
            put("encrypted_response_enc_values_supported", listOf("A256GCM", "A128CBC-HS256"))
        }
        val params = respond(dcqlRequest(dcqlSdJwt("pid"), responseMode = "direct_post.jwt", clientMetadata = metadata))

        assertEquals(EncryptionMethod.A128CBC_HS256, decrypt(params.getValue("response")).header.encryptionMethod)
    }

    @Test
    fun `direct_post dot jwt with only a jwks defaults to A128GCM`() {
        val params = respond(
            dcqlRequest(dcqlSdJwt("pid"), responseMode = "direct_post.jwt", clientMetadata = encryptionMetadata(verifierKey, enc = null)),
        )
        assertEquals(EncryptionMethod.A128GCM, decrypt(params.getValue("response")).header.encryptionMethod)
    }

    @Test
    fun `defect - an enc the SDK does not support throws out of the handler`() {
        val request = dcqlRequest(
            dcqlSdJwt("pid"),
            responseMode = "direct_post.jwt",
            clientMetadata = encryptionMetadata(verifierKey, enc = "A256CBC-HS512"),
        )
        assertThrows(IllegalArgumentException::class.java) { respond(request) }
    }

    @Test
    fun `defect - an alg other than ECDH-ES throws out of the handler`() {
        val request = dcqlRequest(
            dcqlSdJwt("pid"),
            responseMode = "direct_post.jwt",
            clientMetadata = encryptionMetadata(verifierKey, alg = "ECDH-ES+A128KW"),
        )
        assertThrows(IllegalArgumentException::class.java) { respond(request) }
    }

    @Test
    fun `dc_api rewrites the request's client id with an origin prefix`() {
        val request = dcqlRequest(dcqlSdJwt("pid"), responseMode = "dc_api")
        val params = respond(request)

        assertEquals("origin:$CLIENT_ID", request.clientId)
        val kb = keyBindingJwt(json(params["vp_token"]).asJsonObject.getAsJsonArray("pid")[0].asString)
        assertEquals("origin:$CLIENT_ID", kb.jwtClaimsSet.audience.single())
    }

    @Test
    fun `iar-post wraps the presentation in auth_session and openid4vp_presentation`() {
        val request = dcqlRequest(dcqlSdJwt("pid"), responseMode = "iar-post").apply { authSession = "as-1" }
        val params = respond(request)

        assertEquals(setOf("auth_session", "openid4vp_presentation"), params.keys)
        assertEquals("as-1", params["auth_session"])
        val inner = json(params["openid4vp_presentation"]).asJsonObject
        assertTrue(inner.has("vp_token"))
        assertTrue(inner.has("state"))
    }

    @Test
    fun `iar-post dot jwt wraps an encrypted response the same way`() {
        val request = dcqlRequest(
            dcqlSdJwt("pid"),
            responseMode = "iar-post.jwt",
            clientMetadata = encryptionMetadata(verifierKey),
        ).apply { authSession = "as-2" }
        val params = respond(request)

        assertEquals("as-2", params["auth_session"])
        val inner = json(params["openid4vp_presentation"]).asJsonObject
        decrypt(inner["response"].asString)
    }

    @Test
    fun `an absent response mode is treated as direct_post`() {
        val request = dcqlRequest(dcqlSdJwt("pid")).apply { responseMode = null }
        val params = respond(request)
        assertEquals(setOf("vp_token", "state"), params.keys)
    }

    @Test
    fun `defect - an unsupported response mode yields an empty map rather than an error`() {
        assertTrue(respond(dcqlRequest(dcqlSdJwt("pid"), responseMode = "fragment")).isEmpty())
    }
}
