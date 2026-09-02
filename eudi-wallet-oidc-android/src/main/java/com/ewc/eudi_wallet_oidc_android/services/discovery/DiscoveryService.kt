package com.ewc.eudi_wallet_oidc_android.services.discovery

import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.WrappedAuthConfigResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedIssuerConfigResponse
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.AuthServerMetadataResolver
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.AuthorizationServerSelection
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.AuthorizationServerSelector
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.DiscoveredAuthServerMetadata
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.DiscoveredIssuerMetadata
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.DiscoveryPolicy
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.IssuerMetadataResolver
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.SignatureValidatorSignedMetadataVerifier
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.MetadataSignerTrust
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.RejectingSignedMetadataVerifier
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.SignedMetadataVerifier

/**
 * Credential Issuer and Authorization Server metadata discovery.
 *
 * A delegation to `metadata/`, where URL construction, retrieval, trust in signed documents, spec
 * revision and conformance are each a separate, testable piece. The two interface methods keep
 * their exact signatures, so hosts need no change.
 *
 * @param policy what to accept. [DiscoveryPolicy.Default] preserves this SDK's existing reach;
 *   [DiscoveryPolicy.Strict] is OpenID4VCI 1.0 as written and will reject pre-1.0 issuers.
 * @param signedMetadataVerifier establishes trust in signed metadata. The default verifies the
 *   signature and accepts any signer that produced a valid one; see
 *   [MetadataSignerTrust.SignatureOnly] for what that does and does not prove, and pass a
 *   [SignatureValidatorSignedMetadataVerifier] with a real [MetadataSignerTrust] to check the
 *   signer against a trust list. [RejectingSignedMetadataVerifier] refuses signed metadata
 *   outright, which is always safe: section 12.2.2 requires every issuer to serve unsigned JSON.
 */
class DiscoveryService(
    private val policy: DiscoveryPolicy = DiscoveryPolicy.Default,
    private val signedMetadataVerifier: SignedMetadataVerifier = SignatureValidatorSignedMetadataVerifier(),
) : DiscoveryServiceInterface {

    private val issuerResolver = IssuerMetadataResolver(
        policy = policy,
        signedMetadataVerifier = signedMetadataVerifier,
    )

    private val authServerResolver = AuthServerMetadataResolver(
        policy = policy,
        signedMetadataVerifier = signedMetadataVerifier,
    )

    private val authorizationServerSelector = AuthorizationServerSelector()

    /**
     * The Credential Issuer's metadata.
     *
     * @param credentialIssuerWellKnownURI the Credential Issuer Identifier, with or without a
     *   `/.well-known/openid-credential-issuer` segment; both spec URL layouts are recognised and
     *   stripped back to the identifier before the request URLs are built.
     * @return never null. A failure carries an `errorResponse` rather than an empty wrapper, so a
     *   caller can always tell what went wrong and always has something to show.
     */
    override suspend fun getIssuerConfig(
        credentialIssuerWellKnownURI: String?
    ): WrappedIssuerConfigResponse = issuerResolver.resolve(credentialIssuerWellKnownURI).response

    /** The authorization server's metadata. @see getIssuerConfig */
    override suspend fun getAuthConfig(
        authorisationServerWellKnownURI: String?
    ): WrappedAuthConfigResponse = authServerResolver.resolve(authorisationServerWellKnownURI).response

    /**
     * As [getIssuerConfig], plus which URL layout answered, the media type, and which spec
     * revision the document was. For diagnostics and for exercising this function on its own; the
     * wallet reads [getIssuerConfig].
     */
    suspend fun getIssuerConfigDetailed(
        credentialIssuerWellKnownURI: String?
    ): DiscoveredIssuerMetadata = issuerResolver.resolve(credentialIssuerWellKnownURI)

    /** @see getIssuerConfigDetailed */
    suspend fun getAuthConfigDetailed(
        authorisationServerWellKnownURI: String?
    ): DiscoveredAuthServerMetadata = authServerResolver.resolve(authorisationServerWellKnownURI)

    /**
     * Which authorization server to use, per OpenID4VCI 1.0 section 12.2.4.
     *
     * Handles the cases a host implementing this itself tends to miss: an absent
     * `authorization_servers` means the Credential Issuer is its own authorization server, and an
     * offer naming a server the issuer does not list must stop the flow rather than fall back.
     *
     * @throws com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.DiscoveryException.Invalid
     *   when the spec says the flow must not proceed.
     */
    fun selectAuthorizationServer(
        issuerConfig: IssuerWellKnownConfiguration?,
        credentialOffer: CredentialOffer? = null,
    ): AuthorizationServerSelection = authorizationServerSelector.select(
        issuerConfig,
        authorizationServerSelector.hintFrom(credentialOffer),
    )
}
