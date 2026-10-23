package com.ewc.eudi_wallet_oidc_android.services.verification.client

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessEbsiJWKFromKID
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessJWKFromKID
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessKeyJWKFromKID
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessWebJWKFromKID
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestException
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestPolicy
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import java.util.Date

/**
 * Section 5.9.3 `verifier_attestation`: the identifier "MUST equal the sub claim value in the
 * Verifier attestation JWT. The request MUST be signed with the private key corresponding to the
 * public key in the cnf claim in the Verifier attestation JWT ... The Verifier attestation JWT
 * MUST be added to the jwt JOSE Header of the request object. The Wallet MUST validate the
 * signature on the Verifier attestation JWT. The iss claim value of the Verifier Attestation JWT
 * MUST identify a party the Wallet trusts for issuing Verifier Attestation JWTs. If the Wallet
 * cannot establish trust, it MUST refuse the request. If the issuer of the Verifier Attestation
 * JWT adds a redirect_uris claim to the attestation, the Wallet MUST ensure the redirect_uri
 * request parameter value exactly matches one of the redirect_uris claim entries."
 *
 * Trust in the attester is anchoring, handled the same way as an x509 chain: an attestation
 * signed by one of [PresentationRequestPolicy.verifierAttestationIssuerKeys] is anchored. One
 * whose `iss` is a DID that resolves to the signing key is self-consistent and reported as
 * verified but not anchored, leaving the trust decision to the host; a policy with
 * `requireAnchoredClients` refuses it. Anything else cannot be checked and is refused.
 */
class VerifierAttestationClientHandler : ClientIdentifierHandler {

    override val prefixes = setOf(ClientIdPrefix.VERIFIER_ATTESTATION)

    override suspend fun verify(request: PresentationRequest, identifier: ClientIdentifier, policy: PresentationRequestPolicy): VerifierIdentity {
        val jwt = signedRequestObject(request, identifier.prefix)

        val attestation = (jwt.header.getCustomParam("jwt") as? String)?.let {
            try { SignedJWT.parse(it) } catch (e: Exception) { null }
        } ?: throw PresentationRequestException.ClientNotVerified("the request object carries no verifier attestation JWT in its jwt header")
        val claims = attestation.jwtClaimsSet

        if (claims.subject != identifier.identifier) {
            throw PresentationRequestException.ClientNotVerified("the verifier attestation sub does not match the client identifier")
        }
        if (claims.expirationTime?.before(Date()) == true) {
            throw PresentationRequestException.ClientNotVerified("the verifier attestation has expired")
        }

        @Suppress("UNCHECKED_CAST")
        val cnfJwk = ((claims.getClaim("cnf") as? Map<String, Any?>)?.get("jwk") as? Map<String, Any?>)
            ?.let { try { JWK.parse(it) } catch (e: Exception) { null } }
            ?: throw PresentationRequestException.ClientNotVerified("the verifier attestation carries no cnf key")
        if (!RequestObjectCertificates.verifySignature(jwt, cnfJwk)) {
            throw PresentationRequestException.ClientNotVerified("the request object is not signed with the attested key")
        }

        val trustedKeys = policy.verifierAttestationIssuerKeys?.keys.orEmpty()
        val anchored = trustedKeys.any { RequestObjectCertificates.verifySignature(attestation, it) }
        if (!anchored) {
            val issuer = claims.issuer ?: ""
            val issuerKey = attesterKey(issuer, attestation)
                ?: throw PresentationRequestException.ClientNotVerified("the verifier attestation is not signed by a trusted issuer")
            if (!RequestObjectCertificates.verifySignature(attestation, issuerKey)) {
                throw PresentationRequestException.ClientNotVerified("the verifier attestation signature does not verify against its issuer $issuer")
            }
        }

        val allowed = try { claims.getStringListClaim("redirect_uris") } catch (e: Exception) { null }
        val target = request.redirectUri?.takeIf { it.isNotBlank() } ?: request.responseUri
        if (allowed != null && target != null && target !in allowed) {
            throw PresentationRequestException.ClientNotVerified("the redirect_uri is not among the attestation's redirect_uris")
        }

        return VerifierIdentity(
            identifier = identifier,
            verified = true,
            anchored = anchored,
            reason = if (anchored) null else "the attester ${claims.issuer} is not a configured trusted issuer; the attestation is self-consistent only",
        )
    }

    /** The attester's key when `iss` is a DID this SDK can resolve; null otherwise. */
    private suspend fun attesterKey(issuer: String, attestation: SignedJWT): JWK? = try {
        when {
            issuer.startsWith("did:key:z") -> ProcessKeyJWKFromKID().processKeyJWKFromKID(issuer, attestation.header.algorithm)
            issuer.startsWith("did:jwk:") -> ProcessJWKFromKID().processJWKFromKID(issuer)
            issuer.startsWith("did:ebsi:") -> ProcessEbsiJWKFromKID().processEbsiJWKFromKID(issuer)
            issuer.startsWith("did:web:") -> ProcessWebJWKFromKID().processWebJWKFromKID(attestation.header.keyID?.takeIf { it.startsWith(issuer) } ?: issuer)
            else -> null
        }
    } catch (e: Exception) {
        null
    }
}
