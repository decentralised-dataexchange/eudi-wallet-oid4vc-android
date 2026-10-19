package com.ewc.eudi_wallet_oidc_android.services.verification

import co.nstant.`in`.cbor.model.Map as CborMap
import com.ewc.eudi_wallet_oidc_android.models.CredentialList
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.DID
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.STATE
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.dcqlJwt
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.dcqlMdoc
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.dcqlRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.dcqlSdJwt
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.decodeCbor
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.encryptionMetadata
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.json
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.jwtVc
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.key
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.keyBindingJwt
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.mdoc
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.sdJwt
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.verifierEncryptionKey
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse.AuthorisationResponseHandler
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Characterisation of the DCQL response path as it behaves today. See
 * [PexResponseCharacterisationTest] for the purpose of these tests.
 */
class DcqlResponseCharacterisationTest {

    private val holder = key()

    private fun respond(
        request: com.ewc.eudi_wallet_oidc_android.models.PresentationRequest,
        credentials: List<List<String>>,
        keys: List<List<JWK?>>? = credentials.map { group -> group.map { holder } },
    ): Map<String, String> = runBlocking {
        AuthorisationResponseHandler().prepareAuthorisationResponseV2(
            presentationRequest = request,
            credentialList = credentials,
            did = DID,
            jwk = holder,
            isScaFlow = false,
            jwkList = keys,
        )
    }

    private fun vpToken(params: Map<String, String>) = json(params["vp_token"]).asJsonObject

    @Test
    fun `a 1_0 verifier gets one list per credential id and no presentation_submission`() {
        val params = respond(dcqlRequest(dcqlSdJwt("pid")), listOf(listOf(sdJwt())))

        assertEquals(setOf("vp_token", "state"), params.keys)
        assertFalse(params.containsKey("presentation_submission"))
        val token = vpToken(params)
        val presented = token.getAsJsonArray("pid")
        assertEquals(1, presented.size())
        val kb = keyBindingJwt(presented[0].asString)
        assertTrue(kb.verify(ECDSAVerifier(holder.toECPublicKey())))
        assertEquals(STATE, params["state"])
    }

    @Test
    fun `a draft_23 verifier gets a bare string per credential id`() {
        val request = dcqlRequest(
            dcqlSdJwt("pid"),
            clientMetadata = encryptionMetadata(verifierEncryptionKey(), version = "draft_23"),
        )
        val params = respond(request, listOf(listOf(sdJwt())))

        assertTrue(vpToken(params)["pid"].isJsonPrimitive)
        keyBindingJwt(vpToken(params)["pid"].asString)
    }

    @Test
    fun `an entry answered with two credentials maps to a two element list`() {
        val params = respond(
            dcqlRequest(dcqlSdJwt("a", "urn:a"), dcqlSdJwt("b", "urn:b")),
            listOf(listOf(sdJwt("urn:a")), listOf(sdJwt("urn:b"), sdJwt("urn:b"))),
        )

        val token = vpToken(params)
        assertEquals(1, token.getAsJsonArray("a").size())
        assertEquals(2, token.getAsJsonArray("b").size())
    }

    @Test
    fun `each presented credential is bound with its own key`() {
        val k1 = key("k1")
        val k2 = key("k2")
        val params = respond(
            dcqlRequest(dcqlSdJwt("pid")),
            listOf(listOf(sdJwt(), sdJwt())),
            keys = listOf(listOf(k1, k2)),
        )

        val presented = vpToken(params).getAsJsonArray("pid").map { keyBindingJwt(it.asString) }
        assertTrue(presented[0].verify(ECDSAVerifier(k1.toECPublicKey())))
        assertTrue(presented[1].verify(ECDSAVerifier(k2.toECPublicKey())))
        assertFalse(presented[1].verify(ECDSAVerifier(k1.toECPublicKey())))
    }

    @Test
    fun `a missing per credential key falls back to the holder key`() {
        val params = respond(dcqlRequest(dcqlSdJwt("pid")), listOf(listOf(sdJwt())), keys = listOf(listOf(null)))

        val kb = keyBindingJwt(vpToken(params).getAsJsonArray("pid")[0].asString)
        assertTrue(kb.verify(ECDSAVerifier(holder.toECPublicKey())))
    }

    @Test
    fun `an mdoc entry yields a base64url DeviceResponse`() {
        val params = respond(dcqlRequest(dcqlMdoc("mdl")), listOf(listOf(mdoc(holder))))

        val presented = vpToken(params).getAsJsonArray("mdl")[0].asString
        val deviceResponse = decodeCbor(presented) as CborMap
        assertEquals(3, deviceResponse.keys.size) // version, documents, status
    }

    @Test
    fun `a jwt_vc_json entry yields a W3C presentation`() {
        val params = respond(dcqlRequest(dcqlJwt("vc")), listOf(listOf(jwtVc())))

        val vp = SignedJWT.parse(vpToken(params).getAsJsonArray("vc")[0].asString)
        assertTrue(vp.jwtClaimsSet.getJSONObjectClaim("vp").containsKey("verifiableCredential"))
    }

    @Test
    fun `defect - a credential count that differs from the query count yields an empty response`() {
        val params = respond(dcqlRequest(dcqlSdJwt("a"), dcqlSdJwt("b")), listOf(listOf(sdJwt())))

        // Nothing is built and nothing says why; the caller sees an empty parameter map.
        assertTrue(params.isEmpty())
    }

    @Test
    fun `defect - an entry whose meta names no format is sent as an empty value`() {
        val typeless = CredentialList(id = "x", format = "dc+sd-jwt")
        val params = respond(dcqlRequest(typeless), listOf(listOf(sdJwt())))

        // The format is derived from `meta`, not from `format`, so this entry builds nothing.
        val token = vpToken(params)
        assertTrue(!token.has("x") || token["x"].isJsonNull)
    }

    @Test
    fun `an entry with no selected credential is left out of the token`() {
        val params = respond(dcqlRequest(dcqlSdJwt("a"), dcqlSdJwt("b")), listOf(listOf(sdJwt()), emptyList()))

        val token = vpToken(params)
        assertTrue(token.has("a"))
        assertFalse(token.has("b"))
    }

    @Test
    fun `legacy V1 entry point wraps the single token in a list`() {
        val params = runBlocking {
            AuthorisationResponseHandler().prepareAuthorisationResponse(
                presentationRequest = dcqlRequest(dcqlSdJwt("pid")),
                credentialList = listOf(sdJwt()),
                did = DID,
                jwk = holder,
            )
        }
        assertEquals(1, vpToken(params).getAsJsonArray("pid").size())
    }
}
