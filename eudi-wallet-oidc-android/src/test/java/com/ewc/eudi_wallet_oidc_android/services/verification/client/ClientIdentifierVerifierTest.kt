package com.ewc.eudi_wallet_oidc_android.services.verification.client

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.did.DIDService
import com.ewc.eudi_wallet_oidc_android.services.verification.CertificateFixtures
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestException
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestOutcome
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestPolicy
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestResolver
import com.ewc.eudi_wallet_oidc_android.services.verification.request.RequestUriMethod
import com.google.gson.JsonParser
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.util.Base64
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.URLEncoder
import java.security.cert.X509Certificate
import java.util.Date

/**
 * One case per row of the leg 2 matrix in VERIFICATION_REVAMP_PLAN_ANDROID.md. The x509 rows use
 * two self-signed P-256 certificates made with openssl, one with SAN DNS verifier.example.com
 * and one with other.example.com, embedded so the tests need no certificate library.
 */
class ClientIdentifierVerifierTest {

    // ── material ─────────────────────────────────────────────────────────────

    private val verifierCert get() = CertificateFixtures.verifierCert
    private val otherCert get() = CertificateFixtures.otherCert
    private val verifierKey get() = CertificateFixtures.verifierKey
    private val otherKey get() = CertificateFixtures.otherKey

    private val sanDns = "x509_san_dns:verifier.example.com"
    private val responseUri = "https://verifier.example.com/response"

    private fun requestObject(
        signer: ECKey,
        clientId: String,
        x5c: List<X509Certificate>? = null,
        kid: String? = null,
        attestation: String? = null,
        responseUri: String? = this.responseUri,
    ): String {
        val header = JWSHeader.Builder(JWSAlgorithm.ES256).apply {
            x5c?.let { chain -> x509CertChain(chain.map { Base64.encode(it.encoded) }) }
            kid?.let { keyID(it) }
            attestation?.let { customParam("jwt", it) }
        }.build()
        val claims = JWTClaimsSet.Builder()
            .claim("client_id", clientId)
            .claim("response_type", "vp_token")
            .claim("response_mode", "direct_post")
            .claim("response_uri", responseUri)
            .claim("nonce", "n1")
            .build()
        return SignedJWT(header, claims).apply { sign(ECDSASigner(signer)) }.serialize()
    }

    private fun request(
        clientId: String?,
        requestObject: String? = null,
        responseMode: String? = "direct_post",
        responseUri: String? = this.responseUri,
        redirectUri: String? = null,
        clientIdScheme: String? = null,
    ) = PresentationRequest(
        clientId = clientId,
        request = requestObject,
        responseMode = responseMode,
        responseUri = responseUri,
        redirectUri = redirectUri,
        clientIdScheme = clientIdScheme,
        nonce = "n1",
    )

    private fun verify(request: PresentationRequest, policy: PresentationRequestPolicy = PresentationRequestPolicy.Default): VerifierIdentity =
        runBlocking { ClientIdentifierVerifier().verify(request, policy) }

    private fun refused(request: PresentationRequest, policy: PresentationRequestPolicy = PresentationRequestPolicy.Default): String {
        try {
            verify(request, policy)
        } catch (e: PresentationRequestException) {
            return e.message!!
        }
        throw AssertionError("expected the request to be refused")
    }

    // ── parsing ──────────────────────────────────────────────────────────────

    @Test
    fun `a client_id is split at the first colon when the prefix is known`() {
        val parsed = ClientIdentifier.parse("x509_san_dns:verifier.example.com")
        assertEquals(ClientIdPrefix.X509_SAN_DNS, parsed.prefix)
        assertEquals("verifier.example.com", parsed.identifier)
        assertEquals("x509_san_dns:verifier.example.com", parsed.original)

        val did = ClientIdentifier.parse("decentralized_identifier:did:web:verifier.example")
        assertEquals("did:web:verifier.example", did.identifier)
    }

    @Test
    fun `the draft client_id_scheme parameter names the prefix for a bare client_id`() {
        val parsed = ClientIdentifier.parse("verifier.example.com", legacyScheme = "x509_san_dns")
        assertEquals(ClientIdPrefix.X509_SAN_DNS, parsed.prefix)
        assertEquals("verifier.example.com", parsed.identifier)

        val redirect = ClientIdentifier.parse("https://verifier.example/cb", legacyScheme = "redirect_uri")
        assertEquals(ClientIdPrefix.REDIRECT_URI, redirect.prefix)
        assertEquals("https://verifier.example/cb", redirect.identifier)
    }

    @Test
    fun `the prefixed x509_san_uri form is stripped and the bare draft form is kept whole`() {
        val prefixed = ClientIdentifier.parse("x509_san_uri:https://verifier.example/cb")
        assertEquals(ClientIdPrefix.X509_SAN_URI, prefixed.prefix)
        assertEquals("https://verifier.example/cb", prefixed.identifier)
        assertEquals("x509_san_uri:https://verifier.example/cb", prefixed.original)

        val bare = ClientIdentifier.parse("https://verifier.example/cb", legacyScheme = "x509_san_uri")
        assertEquals(ClientIdPrefix.X509_SAN_URI, bare.prefix)
        assertEquals("https://verifier.example/cb", bare.identifier)
    }

    @Test
    fun `no colon, an https URL and an unknown prefix are pre-registered clients`() {
        assertEquals(ClientIdPrefix.PRE_REGISTERED, ClientIdentifier.parse("example-client").prefix)
        val https = ClientIdentifier.parse("https://verifier.example")
        assertEquals(ClientIdPrefix.HTTPS, https.prefix)
        assertEquals("https://verifier.example", https.identifier)
        val unknown = ClientIdentifier.parse("entity_id:abc")
        assertEquals(ClientIdPrefix.PRE_REGISTERED, unknown.prefix)
        assertEquals("entity_id", unknown.unrecognisedPrefix)
    }

    // ── 2.1 / 2.2 redirect_uri ───────────────────────────────────────────────

    @Test
    fun `2_1 redirect_uri carries no authentication and fills the missing response or redirect URI`() {
        val direct = request("redirect_uri:$responseUri", responseUri = null)
        val identity = verify(direct)
        assertFalse(identity.verified)
        assertEquals(responseUri, direct.responseUri)

        val fragment = request("redirect_uri:https://verifier.example/cb", responseMode = "fragment", responseUri = null)
        verify(fragment)
        assertEquals("https://verifier.example/cb", fragment.redirectUri)
        assertNull(fragment.responseUri)
    }

    @Test
    fun `2_2 a signed redirect_uri request is accepted and the signature reported as ignored`() {
        val identity = verify(request("redirect_uri:$responseUri", requestObject(verifierKey, "redirect_uri:$responseUri")))
        assertFalse(identity.verified)
        assertTrue(identity.reason!!.contains("ignored"))
    }

    // ── 2.3 / 2.4 x509_san_dns ───────────────────────────────────────────────

    @Test
    fun `2_3 x509_san_dns verifies the SAN and the signature, and anchors only with configured roots`() {
        val req = request(sanDns, requestObject(verifierKey, sanDns, x5c = listOf(verifierCert)))

        val identity = verify(req)
        assertTrue(identity.verified)
        assertFalse(identity.anchored)
        assertEquals(listOf(verifierCert), identity.certificateChain)
        assertEquals(true, identity.redirectUriBound)

        val anchored = verify(req, PresentationRequestPolicy(trustAnchors = listOf(verifierCert)))
        assertTrue(anchored.anchored)

        val wrongRoot = refused(req, PresentationRequestPolicy(trustAnchors = listOf(otherCert)))
        assertTrue(wrongRoot.contains("trusted anchor"))
    }

    @Test
    fun `2_4 x509_san_dns refuses a SAN mismatch, a foreign key, a missing chain and a missing request object`() {
        assertTrue(refused(request(sanDns, requestObject(otherKey, sanDns, x5c = listOf(otherCert)))).contains("dNSName"))
        assertTrue(refused(request(sanDns, requestObject(otherKey, sanDns, x5c = listOf(verifierCert)))).contains("not signed with the leaf"))
        assertTrue(refused(request(sanDns, requestObject(verifierKey, sanDns))).contains("no x5c"))
        assertTrue(refused(request(sanDns)).contains("requires a signed request object"))
    }

    @Test
    fun `2_3b the redirect URI binding is reported, not enforced`() {
        val req = request(sanDns, requestObject(verifierKey, sanDns, x5c = listOf(verifierCert), responseUri = "https://elsewhere.example/r"), responseUri = "https://elsewhere.example/r")
        assertEquals(false, verify(req).redirectUriBound)
    }

    // ── 2.5 x509_hash ────────────────────────────────────────────────────────

    @Test
    fun `2_5 x509_hash verifies the leaf hash and the signature`() {
        val hash = RequestObjectCertificates.sha256Base64Url(verifierCert)
        val clientId = "x509_hash:$hash"
        val ok = verify(request(clientId, requestObject(verifierKey, clientId, x5c = listOf(verifierCert))))
        assertTrue(ok.verified)
        assertFalse(ok.anchored)

        val wrong = "x509_hash:${RequestObjectCertificates.sha256Base64Url(otherCert)}"
        assertTrue(refused(request(wrong, requestObject(verifierKey, wrong, x5c = listOf(verifierCert)))).contains("hash"))
    }

    // ── 2.6 decentralized_identifier ─────────────────────────────────────────

    @Test
    fun `2_6 decentralized_identifier verifies with the key the kid names under the client DID`() {
        val holder = VerificationFixtures.key("verifier-did")
        val did = DIDService().createES256DID(holder)
        val clientId = "decentralized_identifier:$did"
        val kid = "$did#${did.removePrefix("did:key:")}"

        assertTrue(verify(request(clientId, requestObject(holder, clientId, kid = kid))).verified)

        val stranger = VerificationFixtures.key("stranger")
        val strangerDid = DIDService().createES256DID(stranger)
        val foreign = refused(request(clientId, requestObject(stranger, clientId, kid = "$strangerDid#${strangerDid.removePrefix("did:key:")}")))
        assertTrue(foreign.contains("kid does not belong"))

        assertTrue(refused(request(clientId, requestObject(holder, clientId))).contains("no kid"))

        // The draft bare-DID scheme follows the same rules.
        assertTrue(verify(request(did, requestObject(holder, did, kid = kid))).verified)
    }

    // ── 2.7 verifier_attestation ─────────────────────────────────────────────

    private val attester = VerificationFixtures.key("attester")
    private val attesterKeys = JWKSet(attester.toPublicJWK())

    private fun attestation(sub: String, signer: ECKey = attester, cnf: ECKey = verifierKey, redirectUris: List<String>? = null): String {
        val claims = JWTClaimsSet.Builder()
            .issuer("https://attester.example")
            .subject(sub)
            .expirationTime(Date(System.currentTimeMillis() + 600_000))
            .claim("cnf", mapOf("jwk" to cnf.toPublicJWK().toJSONObject()))
            .apply { redirectUris?.let { claim("redirect_uris", it) } }
            .build()
        return SignedJWT(JWSHeader.Builder(JWSAlgorithm.ES256).keyID(signer.keyID).build(), claims)
            .apply { sign(ECDSASigner(signer)) }.serialize()
    }

    @Test
    fun `2_7 verifier_attestation verifies sub, the attested key and a trusted attester`() {
        val clientId = "verifier_attestation:verifier.example"
        val policy = PresentationRequestPolicy(verifierAttestationIssuerKeys = attesterKeys)
        val good = request(clientId, requestObject(verifierKey, clientId, attestation = attestation("verifier.example")))
        val identity = verify(good, policy)
        assertTrue(identity.verified)
        assertTrue(identity.anchored)

        // No configured attester: an https issuer cannot be checked at all.
        assertTrue(refused(good).contains("trusted issuer"))
        assertTrue(refused(request(clientId, requestObject(verifierKey, clientId, attestation = attestation("someone.else"))), policy).contains("sub"))
        assertTrue(refused(request(clientId, requestObject(verifierKey, clientId, attestation = attestation("verifier.example", signer = otherKey))), policy).contains("trusted issuer"))
        assertTrue(refused(request(clientId, requestObject(otherKey, clientId, attestation = attestation("verifier.example"))), policy).contains("attested key"))
        val bound = request(clientId, requestObject(verifierKey, clientId, attestation = attestation("verifier.example", redirectUris = listOf("https://allowed.example/cb"))), redirectUri = "https://other.example/cb")
        assertTrue(refused(bound, policy).contains("redirect_uris"))
    }

    @Test
    fun `2_7b a self-attested verifier whose iss is its own did key is verified but not anchored`() {
        val own = VerificationFixtures.key("self-attester")
        val did = DIDService().createES256DID(own)
        val clientId = "verifier_attestation:https://verifier.example/service"
        val claims = JWTClaimsSet.Builder()
            .issuer(did).subject("https://verifier.example/service")
            .expirationTime(Date(System.currentTimeMillis() + 600_000))
            .claim("cnf", mapOf("jwk" to own.toPublicJWK().toJSONObject()))
            .build()
        val selfAttestation = SignedJWT(JWSHeader.Builder(JWSAlgorithm.ES256).keyID("thumb").build(), claims)
            .apply { sign(ECDSASigner(own)) }.serialize()
        val req = request(clientId, requestObject(own, clientId, kid = "$did#${did.removePrefix("did:key:")}", attestation = selfAttestation))

        val identity = verify(req)
        assertTrue(identity.verified)
        assertFalse(identity.anchored)
        assertTrue(identity.reason!!.contains("not a configured trusted issuer"))

        assertTrue(refused(req, PresentationRequestPolicy(requireAnchoredClients = true)).contains("not a configured trusted issuer"))
        assertTrue(verify(req, PresentationRequestPolicy(verifierAttestationIssuerKeys = JWKSet(own.toPublicJWK()))).anchored)
    }

    @Test
    fun `requireAnchoredClients refuses an unanchored x509 chain and leaves unverified prefixes alone`() {
        val strictAnchors = PresentationRequestPolicy(requireAnchoredClients = true)
        assertTrue(refused(request(sanDns, requestObject(verifierKey, sanDns, x5c = listOf(verifierCert))), strictAnchors).contains("consistency only"))
        assertTrue(verify(request(sanDns, requestObject(verifierKey, sanDns, x5c = listOf(verifierCert))), strictAnchors.copy(trustAnchors = listOf(verifierCert))).anchored)
        assertFalse(verify(request("redirect_uri:$responseUri"), strictAnchors).verified)
    }

    // ── 2.8 / 2.9 / 2.11 / 2.13 ──────────────────────────────────────────────

    @Test
    fun `2_8 openid_federation is refused when enforced and reported when auditing`() {
        val req = request("openid_federation:https://fed.example")
        assertTrue(refused(req).contains("not supported"))
        val audited = verify(req, PresentationRequestPolicy(clientVerification = ClientVerification.Audit))
        assertFalse(audited.verified)
        assertTrue(audited.reason!!.contains("not supported"))
    }

    @Test
    fun `2_9 a pre-registered client passes unverified by default and is refused by the strict policy`() {
        val plain = verify(request("example-client"))
        assertFalse(plain.verified)
        assertEquals(ClientIdPrefix.PRE_REGISTERED, plain.identifier.prefix)
        assertFalse(verify(request("https://issuer.example")).verified)
        assertTrue(refused(request("example-client"), PresentationRequestPolicy.Strict).contains("pre-registered"))
    }

    @Test
    fun `2_11 the origin prefix is never accepted in a request`() {
        assertTrue(refused(request("origin:https://verifier.example")).contains("origin"))
    }

    @Test
    fun `2_13 a missing client_id is refused when enforced and reported when auditing`() {
        assertTrue(refused(request(null)).contains("no client_id"))
        assertFalse(verify(request(null), PresentationRequestPolicy(clientVerification = ClientVerification.Audit)).verified)
    }

    @Test
    fun `Off skips every check`() {
        val bad = request(sanDns, requestObject(otherKey, sanDns, x5c = listOf(otherCert)))
        val identity = verify(bad, PresentationRequestPolicy(clientVerification = ClientVerification.Off))
        assertFalse(identity.verified)
        assertEquals(ClientIdPrefix.X509_SAN_DNS, identity.identifier.prefix)
    }

    // ── advertisement and end to end ─────────────────────────────────────────

    @Test
    fun `the advertised prefixes are the ones the registry can verify`() {
        assertEquals(
            listOf("redirect_uri", "x509_san_dns", "x509_hash", "decentralized_identifier", "verifier_attestation"),
            ClientIdentifierVerifier().supportedPrefixes(PresentationRequestPolicy.Default),
        )
        val advertised = JsonParser.parseString(RequestUriMethod.walletMetadata()).asJsonObject
            .getAsJsonArray("client_id_prefixes_supported").map { it.asString }
        assertFalse("openid_federation" in advertised)
        assertTrue("x509_san_dns" in advertised)
    }

    @Test
    fun `through the resolver an x509_san_dns request is refused without a signed object and resolved with one`() {
        val enc = { v: String -> URLEncoder.encode(v, "UTF-8") }
        val byValue = "openid4vp://?client_id=${enc(sanDns)}&nonce=n1&dcql_query=${enc("""{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}}]}""")}"
        val failed = runBlocking { PresentationRequestResolver().resolve(byValue) } as PresentationRequestOutcome.Failed
        assertTrue(failed.error.errorDescription, failed.error.errorDescription!!.startsWith("The verifier could not be authenticated"))
        assertEquals("invalid_request", failed.error.errorCode)

        val signed = "openid4vp://?client_id=${enc(sanDns)}&request=${enc(requestObject(verifierKey, sanDns, x5c = listOf(verifierCert)))}"
        val resolved = runBlocking { PresentationRequestResolver().resolve(signed) } as PresentationRequestOutcome.Resolved
        assertTrue(resolved.verifier.verified)
        assertEquals(ClientIdPrefix.X509_SAN_DNS, resolved.verifier.identifier.prefix)
    }
}
