package com.ewc.eudi_wallet_oidc_android.services.issue

/**
 * The `client_id` the token request sends, which is also the key proof's `iss`. Null means neither.
 *
 * OpenID4VCI 1.0 Appendix F.1: `iss` "MUST be the client_id of the Client making the Credential
 * request", and "MUST be omitted if the access token ... was obtained from a Pre-Authorized Code
 * Flow through anonymous access to the token endpoint". Section 12.3's
 * `pre-authorized_grant_anonymous_access_supported` (default false) decides that.
 */
object ClientIdentity {

    /** `CredentialOffer.version` for the pre-1.0 drafts. */
    private const val DRAFT_VERSION = 1

    /** @param clientId the wallet's client identity: the WUA `sub`, falling back to the DID. */
    fun resolve(
        isPreAuthorisedCodeFlow: Boolean?,
        preAuthorizedGrantAnonymousAccessSupported: Boolean?,
        version: Int?,
        clientId: String?,
    ): String? {
        val identity = clientId?.takeIf { it.isNotBlank() }
        if (isPreAuthorisedCodeFlow != true) return identity
        // The pre-1.0 drafts never sent client_id with the pre-authorized grant. Unchanged.
        if (version == DRAFT_VERSION) return null
        return if (preAuthorizedGrantAnonymousAccessSupported == true) null else identity
    }
}
