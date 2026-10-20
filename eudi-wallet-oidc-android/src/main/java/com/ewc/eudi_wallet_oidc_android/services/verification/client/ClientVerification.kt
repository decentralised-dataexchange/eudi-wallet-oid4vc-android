package com.ewc.eudi_wallet_oidc_android.services.verification.client

/** How [ClientIdentifierVerifier] reacts when a request fails the rules of its client id prefix. */
enum class ClientVerification {

    /** Refuse the request. OpenID4VP 1.0 as written. */
    Enforced,

    /** Run every check, log the result, carry it in [VerifierIdentity], never refuse. For roll-out. */
    Audit,

    /** Do not check. [VerifierIdentity.verified] is always false. */
    Off,
}
