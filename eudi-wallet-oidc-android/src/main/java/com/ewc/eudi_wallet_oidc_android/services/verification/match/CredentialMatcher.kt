package com.ewc.eudi_wallet_oidc_android.services.verification.match

/** Matches the wallet's credentials against one query language. */
interface CredentialMatcher {

    fun supports(query: PresentationQuery): Boolean

    /**
     * @param credentials the wallet's credentials as stored: SD-JWTs and JWTs in compact form,
     *   mdocs as base64url IssuerSigned. Null and blank entries are ignored.
     */
    suspend fun match(query: PresentationQuery, credentials: List<String?>): CredentialMatches
}
