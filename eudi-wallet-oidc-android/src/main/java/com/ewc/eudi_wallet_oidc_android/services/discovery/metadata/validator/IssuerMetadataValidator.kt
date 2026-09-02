package com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.validator

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.DiscoveryException
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.DiscoveryPolicy
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.IssuerMetadataSpecVersion
import java.net.URI

/**
 * Spec conformance for parsed Credential Issuer metadata, in one place.
 *
 * Validation is deliberately separate from parsing: a parser decides *which revision* a document
 * is, this decides whether it is *usable*. Rules are OpenID4VCI 1.0 section 12.2.4.
 *
 * **Version-aware on purpose.** Applying 1.0's REQUIRED rules to a draft document would reject
 * every pre-1.0 issuer, EBSI included, so a rule only fails a document of the revision that
 * actually defines it. Rules that protect the wallet rather than enforce a spec formality -- the
 * issuer identity check above all -- apply to both.
 */
class IssuerMetadataValidator {

    /**
     * @param expectedIdentifier the Credential Issuer Identifier the document was fetched for.
     * @return the configuration, normalised where the spec defines a default.
     * @throws DiscoveryException.Invalid
     */
    fun validate(
        config: IssuerWellKnownConfiguration,
        specVersion: IssuerMetadataSpecVersion,
        expectedIdentifier: String,
        policy: DiscoveryPolicy,
    ): IssuerWellKnownConfiguration {
        validateIssuerIdentity(config, specVersion, expectedIdentifier, policy)
        validateCredentialEndpoint(config, specVersion, policy)
        validateAuthorizationServers(config)
        return config
    }

    /**
     * Section 12.2.4: `credential_issuer` is REQUIRED and "MUST be identical to the Credential
     * Issuer's identifier value into which the well-known URI string was inserted"; if they differ
     * "the data contained in the response MUST NOT be used".
     *
     * This is the check that stops a redirect or a misconfigured tenant handing us another
     * issuer's endpoints, so it is applied to drafts too -- they predate the rule, but the attack
     * it prevents does not care which revision an issuer implements.
     */
    private fun validateIssuerIdentity(
        config: IssuerWellKnownConfiguration,
        specVersion: IssuerMetadataSpecVersion,
        expectedIdentifier: String,
        policy: DiscoveryPolicy,
    ) {
        val declared = config.credentialIssuer

        if (declared.isNullOrBlank()) {
            if (specVersion == IssuerMetadataSpecVersion.V1_0) {
                throw DiscoveryException.Invalid("The issuer configuration does not name an issuer")
            }
            // Drafts did not require it. Adopt the identifier we asked for so downstream code,
            // which reads credentialIssuer freely, is not handed a null.
            Logger.d(TAG, "Draft issuer metadata declared no credential_issuer; using the requested identifier")
            config.credentialIssuer = expectedIdentifier
            return
        }

        // Compared ignoring a trailing slash, deliberately, and for both revisions.
        //
        // The spec's "no normalization" forbids canonicalising the URL -- case, percent-encoding,
        // default ports -- because those can change which host or path is addressed. A trailing
        // slash cannot. And we strip one ourselves when deriving the identifier from the caller's
        // input, so an exact comparison would reject an issuer that legitimately publishes
        // `https://issuer.example.com/` purely because of a normalisation this SDK performed.
        val matches = declared.trimEnd('/') == expectedIdentifier.trimEnd('/')
        if (matches) return

        // Always said out loud, even when not enforced: an identifier we did not ask for is worth
        // knowing about whether or not it stops the flow.
        Logger.d(
            TAG,
            "Issuer metadata fetched for $expectedIdentifier declares credential_issuer $declared",
        )
        if (policy.requireIssuerIdentifierMatch) {
            throw DiscoveryException.Invalid(
                "The issuer configuration belongs to a different issuer ($declared)"
            )
        }
    }

    /**
     * Section 12.2.4: `credential_endpoint` is REQUIRED and "MUST use the https scheme".
     *
     * Required only of 1.0 documents. The scheme check follows [DiscoveryPolicy.allowedSchemes]
     * rather than the literal https, so a locally hosted issuer still works under [DiscoveryPolicy.Default].
     */
    private fun validateCredentialEndpoint(
        config: IssuerWellKnownConfiguration,
        specVersion: IssuerMetadataSpecVersion,
        policy: DiscoveryPolicy,
    ) {
        val endpoint = config.credentialEndpoint?.trim()

        if (endpoint.isNullOrEmpty()) {
            if (specVersion == IssuerMetadataSpecVersion.V1_0) {
                throw DiscoveryException.Invalid(
                    "The issuer configuration does not name a credential endpoint"
                )
            }
            Logger.d(TAG, "Draft issuer metadata declared no credential_endpoint")
            return
        }

        val scheme = try {
            URI(endpoint).scheme
        } catch (e: Exception) {
            throw DiscoveryException.Invalid(
                "The issuer configuration names an invalid credential endpoint: $endpoint"
            )
        }
        if (!policy.allowsScheme(scheme)) {
            throw DiscoveryException.Invalid(
                "The issuer's credential endpoint uses an unsupported scheme: $scheme"
            )
        }
    }

    /**
     * Section 12.2.4: `authorization_servers` is "a non-empty array of strings". An empty array is
     * a conformance error rather than an absent parameter, and absent has a defined meaning --
     * the issuer is its own authorization server -- so the two must not be conflated.
     */
    private fun validateAuthorizationServers(config: IssuerWellKnownConfiguration) {
        val servers = config.authorizationServers ?: return
        if (servers.isEmpty() || servers.all { it.isBlank() }) {
            throw DiscoveryException.Invalid(
                "The issuer configuration declares an empty authorization_servers array"
            )
        }
    }

    private companion object {
        const val TAG = "IssuerMetadataValidator"
    }
}
