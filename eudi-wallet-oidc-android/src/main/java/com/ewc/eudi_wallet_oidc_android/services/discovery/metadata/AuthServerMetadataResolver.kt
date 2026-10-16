package com.ewc.eudi_wallet_oidc_android.services.discovery.metadata

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedAuthConfigResponse
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.validator.AuthServerMetadataValidator
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.google.gson.Gson

/**
 * Resolves an authorization server identifier into its metadata.
 *
 * OpenID4VCI 1.0 section 12.2.4 names one location: "The actual OAuth 2.0 Authorization Server
 * metadata is obtained from the oauth-authorization-server well-known location as defined in
 * Section 3 of [RFC8414]". Deployments fronted by an OpenID Provider commonly publish only the
 * OpenID Connect Discovery document instead, so `openid-configuration` is tried afterwards behind
 * [DiscoveryPolicy.allowOpenIdConfigurationFallback]. The EBSI conformance authorization server is
 * one of these: its `oauth-authorization-server` location returns 404.
 *
 * Order is spec-first throughout, so a conformant server always answers on the first request.
 */
class AuthServerMetadataResolver(
    private val policy: DiscoveryPolicy = DiscoveryPolicy.Default,
    private val validator: AuthServerMetadataValidator = AuthServerMetadataValidator(),
    private val gson: Gson = Gson(),
    private val signedMetadataVerifier: SignedMetadataVerifier = SignatureValidatorSignedMetadataVerifier(),
) {

    private data class Candidate(val url: String, val wellKnown: String, val form: WellKnownForm)

    suspend fun resolve(input: String?): DiscoveredAuthServerMetadata {
        val identifier = WellKnownUrlBuilder.identifier(input)
            ?: return failure(DiscoveryException.NoIdentifier(), AuthServerMetadataDiagnostics(null))

        val scheme = WellKnownUrlBuilder.scheme(identifier)
        if (scheme.isNullOrBlank()) {
            return failure(
                DiscoveryException.InvalidIdentifier(identifier),
                AuthServerMetadataDiagnostics(identifier),
            )
        }
        if (!policy.allowsScheme(scheme)) {
            return failure(
                DiscoveryException.UnsupportedScheme(scheme),
                AuthServerMetadataDiagnostics(identifier),
            )
        }

        val candidates = candidatesFor(identifier)
        if (candidates.isEmpty()) {
            return failure(
                DiscoveryException.InvalidIdentifier(identifier),
                AuthServerMetadataDiagnostics(identifier),
            )
        }

        var mostInformative: DiscoveryException? = null

        for ((index, candidate) in candidates.withIndex()) {
            try {
                val document = MetadataFetcher.fetch(candidate.url, policy) { requestUrl ->
                    ApiManager.api.getService()?.fetchAuthConfig(
                        requestUrl,
                        MetadataFetcher.acceptHeader(signedMetadataVerifier.supportsSignedMetadata),
                        MetadataFetcher.acceptLanguageHeader(policy),
                    )
                }

                val json = payloadOf(document, identifier)
                val parsed = try {
                    gson.fromJson(json, AuthorisationServerWellKnownConfiguration::class.java)
                } catch (e: Exception) {
                    throw DiscoveryException.Malformed(
                        "The authorization server configuration was not valid JSON"
                    )
                } ?: throw DiscoveryException.Malformed(
                    "The authorization server configuration was empty"
                )

                val config = validator.validate(parsed, identifier)

                if (candidate.wellKnown == WellKnownUrlBuilder.OPENID_CONFIGURATION) {
                    Logger.d(TAG, "Authorization server metadata came from OpenID Connect Discovery: ${candidate.url}")
                }

                return DiscoveredAuthServerMetadata(
                    response = WrappedAuthConfigResponse(authConfig = config),
                    diagnostics = AuthServerMetadataDiagnostics(
                        identifier = identifier,
                        attemptedUrls = candidates.take(index + 1).map { it.url },
                        resolvedUrl = candidate.url,
                        form = candidate.form,
                        contentType = document.contentType,
                        wellKnown = candidate.wellKnown,
                    ),
                )
            } catch (e: DiscoveryException) {
                mostInformative = mostInformative.orMoreInformativeThan(e)
            } catch (e: Exception) {
                Logger.e(TAG, "Unexpected failure resolving authorization server metadata from ${candidate.url}", e)
                mostInformative = mostInformative.orMoreInformativeThan(
                    DiscoveryException.Malformed("The authorization server configuration could not be read")
                )
            }
        }

        return failure(
            mostInformative ?: DiscoveryException.FetchFailed(null, null),
            AuthServerMetadataDiagnostics(
                identifier = identifier,
                attemptedUrls = candidates.map { it.url },
            ),
        )
    }

    /** Spec location first, in both URL layouts, then the OpenID Connect Discovery document. */
    private fun candidatesFor(identifier: String): List<Candidate> {
        val wellKnowns = buildList {
            add(WellKnownUrlBuilder.OAUTH_AUTHORIZATION_SERVER)
            if (policy.allowOpenIdConfigurationFallback) add(WellKnownUrlBuilder.OPENID_CONFIGURATION)
        }

        val seen = LinkedHashMap<String, Candidate>()
        // Insertion form for both documents first, then the suffix form for both, matching the
        // order this SDK has always used so no issuer that works today starts failing.
        for (wellKnown in wellKnowns) {
            WellKnownUrlBuilder.insertionForm(identifier, wellKnown)?.let { url ->
                seen.putIfAbsent(url, Candidate(url, wellKnown, WellKnownForm.Insertion))
            }
        }
        if (policy.allowSuffixWellKnownFallback) {
            for (wellKnown in wellKnowns) {
                val url = WellKnownUrlBuilder.suffixForm(identifier, wellKnown)
                seen.putIfAbsent(url, Candidate(url, wellKnown, WellKnownForm.Suffix))
            }
        }
        return seen.values.toList()
    }

    /**
     * A signed document reaches the verifier; anything else is used as-is.
     *
     * Before this, an authorization server document delivered as a JWT had its payload decoded and
     * trusted with no signature check, which put the token endpoint under the control of whoever
     * could answer the request.
     */
    private suspend fun payloadOf(document: MetadataDocument, identifier: String): String =
        if (document.isJwtMediaType || MetadataFetcher.looksLikeJwt(document.body)) {
            signedMetadataVerifier.verify(document.body.trim(), identifier)
        } else {
            document.body
        }

    private fun failure(
        error: DiscoveryException,
        diagnostics: AuthServerMetadataDiagnostics,
    ): DiscoveredAuthServerMetadata = DiscoveredAuthServerMetadata(
        response = WrappedAuthConfigResponse(
            authConfig = null,
            errorResponse = ErrorResponse(
                error = error.httpStatus,
                errorDescription = error.message,
            ),
        ),
        diagnostics = diagnostics,
    )

    private companion object {
        const val TAG = "AuthServerMetadataResolver"
    }
}
