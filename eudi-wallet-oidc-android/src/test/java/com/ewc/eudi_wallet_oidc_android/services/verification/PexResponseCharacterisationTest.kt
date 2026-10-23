package com.ewc.eudi_wallet_oidc_android.services.verification

import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.CLIENT_ID
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.DID
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.NONCE
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.STATE
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.decodeCbor
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.jwtDescriptor
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.jwtVc
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.json
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.key
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.keyBindingJwt
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.mdoc
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.mdocDescriptor
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.pexRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.sdJwt
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.sdJwtDescriptor
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse.AuthorisationResponseHandler
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jwt.SignedJWT
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.UnicodeString
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Characterisation of the Presentation Exchange response path **as it behaves today**, through
 * the entry point the wallet calls (`AuthorisationResponseHandler.prepareAuthorisationResponseV2`).
 * These tests pin current behaviour, defects included, so the response rewrite in later legs is a
 * refactor with a safety net. A test that documents a defect says so in its name.
 */
class PexResponseCharacterisationTest {

    private val holder = key()

    private fun respond(
        request: com.ewc.eudi_wallet_oidc_android.models.PresentationRequest,
        credentials: List<List<String>>,
        keys: List<List<JWK?>>? = credentials.map { group -> group.map { holder } },
        subJwk: JWK? = holder,
    ): Map<String, String> = runBlocking {
        AuthorisationResponseHandler().prepareAuthorisationResponseV2(
            presentationRequest = request,
            credentialList = credentials,
            did = DID,
            jwk = subJwk,
            isScaFlow = false,
            jwkList = keys,
        )
    }

    private fun descriptorMap(params: Map<String, String>) =
        json(params["presentation_submission"]).asJsonObject.getAsJsonArray("descriptor_map")

    @Test
    fun `one SD-JWT descriptor yields a single bound token and a root path`() {
        val params = respond(pexRequest(sdJwtDescriptor("pid")), listOf(listOf(sdJwt())))

        val vpToken = params.getValue("vp_token")
        assertTrue("single token is sent bare, not as an array", vpToken.startsWith("ey"))
        val kb = keyBindingJwt(vpToken)
        assertTrue(kb.verify(ECDSAVerifier(holder.toECPublicKey())))
        assertEquals(CLIENT_ID, kb.jwtClaimsSet.audience.single())
        assertEquals(NONCE, kb.jwtClaimsSet.getStringClaim("nonce"))
        assertEquals("kb+jwt", kb.header.type.type)
        assertNull("no SCA: no response_mode in the KB-JWT", kb.jwtClaimsSet.getClaim("response_mode"))
        assertNull(kb.jwtClaimsSet.getClaim("amr"))

        val submission = json(params["presentation_submission"]).asJsonObject
        assertEquals("pd-1", submission["definition_id"].asString)
        val entry = descriptorMap(params).single().asJsonObject
        assertEquals("pid", entry["id"].asString)
        assertEquals("$", entry["path"].asString)
        assertEquals("vc+sd-jwt", entry["format"].asString)
        assertEquals(STATE, params["state"])
    }

    @Test
    fun `two SD-JWT descriptors yield a JSON array with indexed paths`() {
        val params = respond(
            pexRequest(sdJwtDescriptor("a"), sdJwtDescriptor("b")),
            listOf(listOf(sdJwt("urn:a")), listOf(sdJwt("urn:b"))),
        )

        val tokens = json(params["vp_token"]).asJsonArray
        assertEquals(2, tokens.size())
        val paths = descriptorMap(params).map { it.asJsonObject["path"].asString }
        assertEquals(listOf("$[0]", "$[1]"), paths)
    }

    @Test
    fun `one jwt_vp descriptor yields one W3C presentation per credential with a nested path`() {
        val params = respond(pexRequest(jwtDescriptor("vc")), listOf(listOf(jwtVc())))

        val vp = SignedJWT.parse(params.getValue("vp_token"))
        assertTrue(vp.verify(ECDSAVerifier(holder.toECPublicKey())))
        assertEquals(CLIENT_ID, vp.jwtClaimsSet.audience.single())
        val presented = (vp.jwtClaimsSet.getJSONObjectClaim("vp")["verifiableCredential"] as List<*>)
        assertEquals(1, presented.size)
        assertTrue("holder is derived from the credential's key", vp.jwtClaimsSet.issuer.startsWith("did:key:"))

        val entry = descriptorMap(params).single().asJsonObject
        assertEquals("$", entry["path"].asString)
        assertEquals("jwt_vp", entry["format"].asString)
        assertEquals("$.vp.verifiableCredential[0]", entry["path_nested"].asJsonObject["path"].asString)
    }

    @Test
    fun `two jwt_vp descriptors are aggregated into one W3C presentation`() {
        val params = respond(
            pexRequest(jwtDescriptor("x"), jwtDescriptor("y")),
            listOf(listOf(jwtVc()), listOf(jwtVc())),
        )

        val vp = SignedJWT.parse(params.getValue("vp_token"))
        val presented = (vp.jwtClaimsSet.getJSONObjectClaim("vp")["verifiableCredential"] as List<*>)
        assertEquals(2, presented.size)
        assertEquals(DID, vp.jwtClaimsSet.issuer)
        val entries = descriptorMap(params).map { it.asJsonObject }
        assertEquals(listOf("$", "$"), entries.map { it["path"].asString })
        assertEquals(
            listOf("$.vp.verifiableCredential[0]", "$.vp.verifiableCredential[1]"),
            entries.map { it["path_nested"].asJsonObject["path"].asString },
        )
    }

    @Test
    fun `SD-JWT plus mdoc descriptors yield a bound SD-JWT and a DeviceResponse`() {
        val params = respond(
            pexRequest(sdJwtDescriptor("pid"), mdocDescriptor("mdl")),
            listOf(listOf(sdJwt()), listOf(mdoc(holder))),
        )

        val tokens = json(params["vp_token"]).asJsonArray.map { it.asString }
        assertEquals(2, tokens.size)
        keyBindingJwt(tokens[0])
        val deviceResponse = decodeCbor(tokens[1]) as CborMap
        assertEquals("1.0", (deviceResponse[UnicodeString("version")] as UnicodeString).string)
        assertTrue(deviceResponse.keys.any { (it as UnicodeString).string == "documents" })
        val entries = descriptorMap(params).map { it.asJsonObject }
        assertEquals(listOf("vc+sd-jwt", "mso_mdoc"), entries.map { it["format"].asString })
        assertEquals(listOf("$[0]", "$[1]"), entries.map { it["path"].asString })
    }

    @Test
    fun `an mdoc with no signing key leaves nothing to send`() {
        val raw = mdoc(null)
        val params = respond(pexRequest(mdocDescriptor("mdl")), listOf(listOf(raw)), keys = listOf(listOf(null)), subJwk = null)

        // Before leg 5 the unsigned IssuerSigned structure itself went out as the vp_token.
        assertTrue(params.isEmpty())
    }

    @Test
    fun `an SD-JWT whose key cannot sign leaves nothing to send`() {
        // A public-only key: it cannot sign.
        val publicOnly = key().toPublicJWK()
        val params = respond(pexRequest(sdJwtDescriptor("pid")), listOf(listOf(sdJwt())), keys = listOf(listOf(publicOnly)), subJwk = publicOnly)

        // Before leg 5 the bare credential went out with the key binding JWT silently missing.
        assertTrue(params.isEmpty())
    }

    @Test
    fun `an EdDSA holder key signs the key binding JWT`() {
        val okp = OctetKeyPairGenerator(Curve.Ed25519).generate()
        val params = respond(pexRequest(sdJwtDescriptor("pid")), listOf(listOf(sdJwt())), keys = listOf(listOf(okp)), subJwk = okp)
        assertEquals("EdDSA", keyBindingJwt(params.getValue("vp_token")).header.algorithm.name)
    }

    @Test
    fun `id_token response type yields only an id token and state`() {
        val params = respond(pexRequest(responseType = "id_token"), emptyList())

        assertEquals(setOf("id_token", "state"), params.keys)
        val idToken = SignedJWT.parse(params["id_token"])
        assertTrue(idToken.verify(ECDSAVerifier(holder.toECPublicKey())))
        assertEquals(DID, idToken.jwtClaimsSet.issuer)
        assertEquals(DID, idToken.jwtClaimsSet.subject)
        assertEquals(CLIENT_ID, idToken.jwtClaimsSet.audience.single())
        assertEquals(NONCE, idToken.jwtClaimsSet.getStringClaim("nonce"))
    }

    @Test
    fun `vp_token plus id_token response type yields both`() {
        val params = respond(pexRequest(sdJwtDescriptor("pid"), responseType = "vp_token+id_token"), listOf(listOf(sdJwt())))

        assertEquals(setOf("vp_token", "id_token", "presentation_submission", "state"), params.keys)
        keyBindingJwt(params.getValue("vp_token"))
        SignedJWT.parse(params["id_token"])
    }

    @Test
    fun `an unknown response type leaves nothing to send`() {
        val params = respond(pexRequest(sdJwtDescriptor("pid"), responseType = "code"), listOf(listOf(sdJwt())))
        assertTrue(params.isEmpty())
    }

    @Test
    fun `a null state is sent as an empty string`() {
        val request = pexRequest(sdJwtDescriptor("pid")).apply { state = null }
        val params = respond(request, listOf(listOf(sdJwt())))
        assertEquals("", params["state"])
    }

    @Test
    fun `legacy V1 entry point produces the same shape for one SD-JWT`() {
        val params = runBlocking {
            AuthorisationResponseHandler().prepareAuthorisationResponse(
                presentationRequest = pexRequest(sdJwtDescriptor("pid")),
                credentialList = listOf(sdJwt()),
                did = DID,
                jwk = holder,
            )
        }
        val kb = keyBindingJwt(params.getValue("vp_token"))
        assertTrue(kb.verify(ECDSAVerifier(holder.toECPublicKey())))
        assertEquals("$", descriptorMap(params).single().asJsonObject["path"].asString)
        assertFalse(params.containsKey("id_token"))
    }
}
