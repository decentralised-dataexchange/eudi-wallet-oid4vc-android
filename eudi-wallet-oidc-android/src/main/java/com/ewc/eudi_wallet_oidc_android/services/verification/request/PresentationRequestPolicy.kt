package com.ewc.eudi_wallet_oidc_android.services.verification.request

import com.ewc.eudi_wallet_oidc_android.services.verification.client.ClientVerification
import com.nimbusds.jose.jwk.JWKSet
import java.security.cert.X509Certificate

/**
 * What the SDK will accept when resolving a presentation request.
 *
 * Kept in one place so a rule can be tightened or relaxed without touching the resolution logic.
 * [Default] preserves the SDK's existing behaviour; [Strict] is OpenID4VP 1.0 as written.
 */
data class PresentationRequestPolicy(

    /**
     * Accept pre-1.0 requests: `presentation_definition`, `presentation_definition_uri` and
     * `client_metadata_uri`. Set false to require a `dcql_query`.
     */
    val allowDraftRequests: Boolean = true,

    /**
     * Accept a request object with `alg: none` for a client identifier prefix other than
     * `redirect_uri`. OpenID4VP 1.0 section 5.9 says a `redirect_uri` request MUST NOT be signed,
     * so that prefix is exempt whatever this says. For every other prefix the signature is what
     * identifies the verifier, so an unsigned object is refused by default.
     */
    val allowUnsignedRequestObjects: Boolean = false,

    /**
     * Refuse a request carrying both `request` and `request_uri`. RFC 9101 section 5: if either
     * parameter is present in the authorization request, the other MUST NOT be.
     */
    val rejectAmbiguousRequests: Boolean = true,

    /**
     * Whether a request that fails the rules of its client identifier prefix (section 5.9.3) is
     * refused, only reported, or not checked at all.
     */
    val clientVerification: ClientVerification = ClientVerification.Enforced,

    /**
     * Accept a `client_id` with no prefix, or with one this SDK does not know, as a pre-registered
     * client (section 5.9.2). Such a request carries no authentication; the host's trust list is
     * what vouches for the client.
     */
    val allowPreRegisteredClients: Boolean = true,

    /**
     * Roots the `x5c` chain of an `x509_san_dns` or `x509_hash` request must end in. Empty means
     * the chain is checked for consistency only and reported as not anchored, leaving the trust
     * decision to the host.
     */
    val trustAnchors: List<X509Certificate> = emptyList(),

    /**
     * Public keys of the parties trusted to issue verifier attestation JWTs. An attestation
     * signed by one of them is anchored. Without a match, a self-consistent attestation (its
     * `iss` is a DID that resolves to the signing key) is verified but not anchored.
     */
    val verifierAttestationIssuerKeys: JWKSet? = null,

    /**
     * Refuse a verified client whose key is not anchored: an x509 chain that ends in none of
     * [trustAnchors], or an attestation from none of [verifierAttestationIssuerKeys]. Off by
     * default because the host's trust list makes that decision today; on in [Strict], which is
     * section 5.9.3 as written.
     */
    val requireAnchoredClients: Boolean = false,

    /**
     * The `transaction_data` types the host can show the user. Section 5.1: "The Wallet MUST
     * return an error if a request contains even one unrecognized transaction data type." Null
     * accepts any type, because only the host knows which it can render.
     */
    val recognisedTransactionDataTypes: Set<String>? = null,
) {
    companion object {

        /** The SDK's existing behaviour. */
        @JvmField
        val Default = PresentationRequestPolicy()

        /** OpenID4VP 1.0 as written: DCQL only, no draft parameters, no pre-registered clients. */
        @JvmField
        val Strict = PresentationRequestPolicy(
            allowDraftRequests = false,
            allowPreRegisteredClients = false,
            requireAnchoredClients = true,
        )
    }
}
