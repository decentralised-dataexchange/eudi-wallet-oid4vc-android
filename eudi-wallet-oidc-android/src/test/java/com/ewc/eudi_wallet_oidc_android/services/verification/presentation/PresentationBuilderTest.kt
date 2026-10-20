package com.ewc.eudi_wallet_oidc_android.services.verification.presentation

import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.UnicodeString
import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.ewc.eudi_wallet_oidc_android.services.sdjwt.SDJWTService
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.CLIENT_ID
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.DOC_TYPE
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.NONCE
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.RESPONSE_URI
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse.AuthorisationResponseHandler
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.legacy.PresentationSubmissionBuilder
import com.ewc.eudi_wallet_oidc_android.services.verification.transaction.TransactionDataHashes
import com.google.gson.JsonParser
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * One case per row of the leg 4 matrix in VERIFICATION_REVAMP_PLAN_ANDROID.md. The leg 0
 * characterisation tests cover the old entry points; these cover the new builders directly.
 */
class PresentationBuilderTest {

    private val holderKey = VerificationFixtures.key("holder")
    private val holder = WalletIdentity(did = VerificationFixtures.DID, jwk = holderKey)
    private val sdJwt = VerificationFixtures.sdJwt()
    private val mdoc = VerificationFixtures.mdoc(holderKey)

    private fun dcqlRequest(vararg ids: String, responseMode: String = "direct_post", clientId: String = CLIENT_ID) = PresentationRequest(
        clientId = clientId, nonce = NONCE, responseUri = RESPONSE_URI, responseMode = responseMode, responseType = "vp_token",
        dcqlQuery = DCQL(credentials = ids.map { VerificationFixtures.dcqlSdJwt(it) }),
    )

    private fun inputs(request: PresentationRequest, vararg extra: Pair<String, Any?>) = PresentationInputs(
        request = request,
        holder = holder,
        transactionDataHashes = (extra.toMap()["hashes"] as? Map<String, List<String>>).orEmpty().mapValues { TransactionDataHashes("sha-256", it.value) },
        strongCustomerAuthentication = extra.toMap()["sca"] == true,
        authentication = extra.toMap()["auth"] as? AuthenticationMethods,
    )

    private fun build(selected: List<SelectedCredential>, inputs: PresentationInputs, lenient: Boolean = false) =
        runBlocking { PresentationBuilder(lenient = lenient).build(selected, inputs) }

    // ── 4.1 / 4.3 / 4.4 / 4.5 / 4.6 SD-JWT ───────────────────────────────────

    @Test
    fun `4_1 an SD-JWT is presented with a key binding JWT bound to the client and the nonce`() {
        val presentation = build(listOf(SelectedCredential("pid", sdJwt, holderKey)), inputs(dcqlRequest("pid"))).single()
        assertEquals(PresentationFormat.SD_JWT, presentation.format)
        assertEquals(listOf("pid"), presentation.entryIds)
        val kb = VerificationFixtures.keyBindingJwt(presentation.token)
        assertEquals("kb+jwt", kb.header.type.type)
        assertEquals(listOf(CLIENT_ID), kb.jwtClaimsSet.audience)
        assertEquals(NONCE, kb.jwtClaimsSet.getStringClaim("nonce"))
        val presented = presentation.token.substringBeforeLast("~") + "~"
        assertEquals(SDJWTService().calculateSHA256Hash(presented), kb.jwtClaimsSet.getStringClaim("sd_hash"))
        assertTrue(kb.verify(ECDSAVerifier(holderKey.toPublicJWK().toECKey())))
        assertNull(kb.jwtClaimsSet.getClaim("transaction_data_hashes"))
        assertNull(kb.jwtClaimsSet.getClaim("response_mode"))
    }

    @Test
    fun `4_3 a key that cannot sign refuses the presentation when strict and forwards it raw when lenient`() {
        val publicOnly = holderKey.toPublicJWK()
        try {
            build(listOf(SelectedCredential("pid", sdJwt, publicOnly)), inputs(dcqlRequest("pid")).copy(holder = null))
            throw AssertionError("expected KeyBindingFailed")
        } catch (e: PresentationException.KeyBindingFailed) {
            assertTrue(e.message!!.contains("pid"))
        }
        val lenient = build(listOf(SelectedCredential("pid", sdJwt, publicOnly)), inputs(dcqlRequest("pid")).copy(holder = null), lenient = true).single()
        assertEquals(sdJwt, lenient.token)
    }

    @Test
    fun `4_4 an EdDSA holder key signs the key binding JWT`() {
        val okp = OctetKeyPairGenerator(Curve.Ed25519).generate()
        val presentation = build(listOf(SelectedCredential("pid", sdJwt, okp)), inputs(dcqlRequest("pid"))).single()
        val kb = VerificationFixtures.keyBindingJwt(presentation.token)
        assertEquals(JWSAlgorithm.EdDSA, kb.header.algorithm)
        assertTrue(kb.verify(Ed25519Verifier(okp.toPublicJWK())))
    }

    @Test
    fun `4_5 transaction data hashes for the entry go into the key binding JWT`() {
        val presentation = build(
            listOf(SelectedCredential("pid", sdJwt, holderKey)),
            inputs(dcqlRequest("pid"), "hashes" to mapOf("pid" to listOf("h1", "h2"), "other" to listOf("h3"))),
        ).single()
        val claims = VerificationFixtures.keyBindingJwt(presentation.token).jwtClaimsSet
        assertEquals(listOf("h1", "h2"), claims.getStringListClaim("transaction_data_hashes"))
        assertEquals("sha-256", claims.getStringClaim("transaction_data_hashes_alg"))
    }

    @Test
    fun `4_6 a strong customer authentication flow reports response_mode and the factors`() {
        val presentation = build(
            listOf(SelectedCredential("pid", sdJwt, holderKey)),
            inputs(dcqlRequest("pid"), "sca" to true, "auth" to AuthenticationMethods(inherence = "fingerprint", knowledge = "other")),
        ).single()
        val claims = VerificationFixtures.keyBindingJwt(presentation.token).jwtClaimsSet
        assertEquals("direct_post", claims.getStringClaim("response_mode"))
        @Suppress("UNCHECKED_CAST")
        val amr = claims.getClaim("amr") as List<Map<String, String>>
        assertEquals(listOf(mapOf("possession" to "key_in_local_native_wscd"), mapOf("inherence" to "fingerprint"), mapOf("knowledge" to "other")), amr)
    }

    // ── 4.7 / 4.8 / 4.9 session transcripts ──────────────────────────────────

    private fun cbor(item: co.nstant.`in`.cbor.model.DataItem) = ByteArrayOutputStream().also { CborEncoder(it).encode(item) }.toByteArray()
    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)

    @Test
    fun `4_7 the redirect flow transcript hashes client_id, nonce, thumbprint and response_uri`() {
        val thumbprint = ByteArray(32) { 7 }
        val info = CborArray().apply { add(UnicodeString(CLIENT_ID)); add(UnicodeString(NONCE)); add(ByteString(thumbprint)); add(UnicodeString(RESPONSE_URI)) }
        val expected = CborArray().apply {
            add(SimpleValue.NULL); add(SimpleValue.NULL)
            add(CborArray().apply { add(UnicodeString("OpenID4VPHandover")); add(ByteString(sha256(cbor(info)))) })
        }
        assertArrayEquals(cbor(expected), SessionTranscript.openId4Vp(CLIENT_ID, NONCE, RESPONSE_URI, thumbprint).bytes)
        assertArrayEquals(cbor(expected), SessionTranscript.forRequest(dcqlRequest("pid"), thumbprint).bytes)

        val unencrypted = CborArray().apply { add(UnicodeString(CLIENT_ID)); add(UnicodeString(NONCE)); add(SimpleValue.NULL); add(UnicodeString(RESPONSE_URI)) }
        val handover = (SessionTranscript.openId4Vp(CLIENT_ID, NONCE, RESPONSE_URI, null).array.dataItems[2] as CborArray)
        assertArrayEquals(sha256(cbor(unencrypted)), (handover.dataItems[1] as ByteString).bytes)
    }

    @Test
    fun `4_8 the DC API transcript uses the bare origin and the DC API handover`() {
        val request = dcqlRequest("pid", responseMode = "dc_api", clientId = "origin:https://verifier.example")
        val info = CborArray().apply { add(UnicodeString("https://verifier.example")); add(UnicodeString(NONCE)); add(SimpleValue.NULL) }
        val handover = SessionTranscript.forRequest(request, null).array.dataItems[2] as CborArray
        assertEquals("OpenID4VPDCAPIHandover", (handover.dataItems[0] as UnicodeString).string)
        assertArrayEquals(sha256(cbor(info)), (handover.dataItems[1] as ByteString).bytes)
    }

    @Test
    fun `4_9 a presentation definition selects the Annex B transcript`() {
        val request = VerificationFixtures.pexRequest(VerificationFixtures.mdocDescriptor())
        val handover = SessionTranscript.forRequest(request, null).array.dataItems[2] as CborArray
        assertEquals(3, handover.dataItems.size)
        assertArrayEquals(sha256(cbor(CborArray().apply { add(UnicodeString(CLIENT_ID)); add(UnicodeString(CLIENT_ID)) })), (handover.dataItems[0] as ByteString).bytes)
        assertArrayEquals(sha256(cbor(CborArray().apply { add(UnicodeString(RESPONSE_URI)); add(UnicodeString(CLIENT_ID)) })), (handover.dataItems[1] as ByteString).bytes)
        assertEquals(NONCE, (handover.dataItems[2] as UnicodeString).string)
    }

    // ── 4.7 / 4.10 / 4.11 mdoc presentations ─────────────────────────────────

    @Test
    fun `4_7b an mdoc becomes a DeviceResponse with one signed document`() {
        val request = PresentationRequest(clientId = CLIENT_ID, nonce = NONCE, responseUri = RESPONSE_URI, responseMode = "direct_post", responseType = "vp_token",
            dcqlQuery = DCQL(credentials = listOf(VerificationFixtures.dcqlMdoc("mdl"))))
        val presentation = build(listOf(SelectedCredential("mdl", mdoc, holderKey)), inputs(request)).single()
        assertEquals(PresentationFormat.MDOC, presentation.format)
        val response = VerificationFixtures.decodeCbor(presentation.token) as CborMap
        val documents = response[UnicodeString("documents")] as CborArray
        assertEquals(1, documents.dataItems.size)
        val document = documents.dataItems[0] as CborMap
        assertEquals(DOC_TYPE, (document[UnicodeString("docType")] as UnicodeString).string)
        val deviceAuth = (document[UnicodeString("deviceSigned")] as CborMap)[UnicodeString("deviceAuth")] as CborMap
        assertTrue(deviceAuth.keys.any { (it as UnicodeString).string == "deviceSignature" })
    }

    @Test
    fun `4_10 an mdoc without a usable key is refused when strict and forwarded raw when lenient`() {
        val request = dcqlRequest("mdl")
        try {
            build(listOf(SelectedCredential("mdl", mdoc, holderKey.toPublicJWK())), inputs(request).copy(holder = null))
            throw AssertionError("expected NoKey")
        } catch (e: PresentationException.NoKey) {
            assertTrue(e.message!!.contains("mdl"))
        }
        assertEquals(mdoc, build(listOf(SelectedCredential("mdl", mdoc, holderKey.toPublicJWK())), inputs(request).copy(holder = null), lenient = true).single().token)
    }

    @Test
    fun `4_11 two mdocs in a presentation definition get one descriptor each at their own position`() {
        val request = VerificationFixtures.pexRequest(VerificationFixtures.mdocDescriptor("a"), VerificationFixtures.mdocDescriptor("b"), VerificationFixtures.sdJwtDescriptor("c"))
        val presentations = build(
            listOf(SelectedCredential("a", mdoc, holderKey), SelectedCredential("b", VerificationFixtures.mdoc(holderKey, "org.iso.other"), holderKey), SelectedCredential("c", sdJwt, holderKey)),
            inputs(request),
        )
        assertEquals(3, presentations.size)
        val submission = PresentationSubmissionBuilder().build(presentations, com.ewc.eudi_wallet_oidc_android.services.verification.PresentationDefinitionProcessor.processPresentationDefinition(request.presentationDefinition))
        assertEquals(listOf("a" to "$[0]", "b" to "$[1]", "c" to "$[2]"), submission.descriptorMap.map { it.id to it.path })
        assertEquals(listOf("mso_mdoc", "mso_mdoc", "vc+sd-jwt"), submission.descriptorMap.map { it.format })

        // And through the previous entry point, which the wallet calls.
        val params = runBlocking {
            AuthorisationResponseHandler().prepareAuthorisationResponseV2(
                presentationRequest = request,
                credentialList = listOf(listOf(mdoc), listOf(VerificationFixtures.mdoc(holderKey, "org.iso.other")), listOf(sdJwt)),
                did = VerificationFixtures.DID, jwk = holderKey,
            )
        }
        val descriptors = JsonParser.parseString(params.getValue("presentation_submission")).asJsonObject.getAsJsonArray("descriptor_map")
        assertEquals(listOf("$[0]", "$[1]", "$[2]"), descriptors.map { it.asJsonObject["path"].asString })
    }

    // ── 4.12 / 4.13 / 4.14 W3C presentations ─────────────────────────────────

    @Test
    fun `4_12 under DCQL each W3C credential gets its own presentation signed with its key`() {
        val otherKey = VerificationFixtures.key("other")
        val request = PresentationRequest(clientId = CLIENT_ID, nonce = NONCE, responseUri = RESPONSE_URI, responseType = "vp_token",
            dcqlQuery = DCQL(credentials = listOf(VerificationFixtures.dcqlJwt("x"), VerificationFixtures.dcqlJwt("y"))))
        val presentations = build(listOf(SelectedCredential("x", VerificationFixtures.jwtVc(), holderKey), SelectedCredential("y", VerificationFixtures.jwtVc(), otherKey)), inputs(request))
        assertEquals(2, presentations.size)
        val second = SignedJWT.parse(presentations[1].token)
        assertTrue(second.verify(ECDSAVerifier(otherKey.toPublicJWK().toECKey())))
        assertEquals(listOf(CLIENT_ID), second.jwtClaimsSet.audience)
        assertEquals(NONCE, second.jwtClaimsSet.getStringClaim("nonce"))
        assertEquals(1, (second.jwtClaimsSet.getJSONObjectClaim("vp")["verifiableCredential"] as List<*>).size)
    }

    @Test
    fun `4_13 and 4_14 under a presentation definition one W3C credential stands alone and several are aggregated`() {
        val one = VerificationFixtures.pexRequest(VerificationFixtures.jwtDescriptor("x"))
        val single = build(listOf(SelectedCredential("x", VerificationFixtures.jwtVc(), holderKey)), inputs(one))
        assertEquals(listOf("x"), single.single().entryIds)
        val singleSubmission = PresentationSubmissionBuilder().build(single, com.ewc.eudi_wallet_oidc_android.services.verification.PresentationDefinitionProcessor.processPresentationDefinition(one.presentationDefinition))
        assertEquals("$", singleSubmission.descriptorMap.single().path)
        assertEquals("$.vp.verifiableCredential[0]", singleSubmission.descriptorMap.single().pathNested?.path)

        val two = VerificationFixtures.pexRequest(VerificationFixtures.jwtDescriptor("x"), VerificationFixtures.jwtDescriptor("y"))
        val aggregated = build(listOf(SelectedCredential("x", VerificationFixtures.jwtVc(), holderKey), SelectedCredential("y", VerificationFixtures.jwtVc(), holderKey)), inputs(two))
        assertEquals(1, aggregated.size)
        assertEquals(listOf("x", "y"), aggregated.single().entryIds)
        val vp = SignedJWT.parse(aggregated.single().token).jwtClaimsSet.getJSONObjectClaim("vp")
        assertEquals(2, (vp["verifiableCredential"] as List<*>).size)
        val submission = PresentationSubmissionBuilder().build(aggregated, com.ewc.eudi_wallet_oidc_android.services.verification.PresentationDefinitionProcessor.processPresentationDefinition(two.presentationDefinition))
        assertEquals(listOf("$.vp.verifiableCredential[0]", "$.vp.verifiableCredential[1]"), submission.descriptorMap.map { it.pathNested?.path })
    }

    // ── 4.16 ─────────────────────────────────────────────────────────────────

    @Test
    fun `4_16 an unrecognised credential format is refused when strict`() {
        try {
            build(listOf(SelectedCredential("x", "not.a.jwt", holderKey)), inputs(dcqlRequest("x")))
            throw AssertionError("expected UnsupportedFormat")
        } catch (e: PresentationException.UnsupportedFormat) {
            assertTrue(e.message!!.contains("x"))
        }
    }
}
