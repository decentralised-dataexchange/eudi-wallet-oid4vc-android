package com.ewc.eudi_wallet_oidc_android.services.verification.client

import java.security.cert.X509Certificate

/**
 * What the client identifier check established about the verifier.
 *
 * Identity and trust are kept apart. [verified] says the request was proven to come from the key
 * the `client_id` names, by the rules of its prefix. [anchored] says that key also chains to a
 * trust anchor the policy supplied. Whether a verified verifier is one the user should share
 * with is the host's decision, typically a trust list lookup on [identifier].
 */
data class VerifierIdentity(
    val identifier: ClientIdentifier,

    /** The request is authenticated as coming from the client the `client_id` names. */
    val verified: Boolean,

    /** The verifying key chains to an anchor in the policy (x509 trust anchors, attestation issuer keys). */
    val anchored: Boolean = false,

    /** The `x5c` chain of the request object, leaf first, for the x509 prefixes. */
    val certificateChain: List<X509Certificate> = emptyList(),

    /**
     * x509_san_dns only. Section 5.9.3: unless the wallet trusts the client, "the FQDN of the
     * redirect_uri value MUST match the Client Identifier". Reported rather than enforced, because
     * the trust decision that waives it is the host's.
     */
    val redirectUriBound: Boolean? = null,

    /** Why [verified] or [anchored] is false, in words for a log line. */
    val reason: String? = null,
)
