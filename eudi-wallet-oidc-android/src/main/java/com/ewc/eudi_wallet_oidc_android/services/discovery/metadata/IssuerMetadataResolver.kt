package com.ewc.eudi_wallet_oidc_android.services.discovery.metadata

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.WrappedIssuerConfigResponse
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.parser.IssuerMetadataParser
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.parser.OpenId4VciV1IssuerMetadataParser
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.parser.legacy.DraftIssuerMetadataParser
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.validator.IssuerMetadataValidator
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.google.gson.JsonObject
import com.google.gson.JsonParser

/**
 * Resolves a Credential Issuer Identifier into its metadata: build the URLs, retrieve, establish
 * trust if the document is signed, pick a parser, validate.
 *
 * The parser registry is ordered and OpenID4VCI 1.0 always comes first, so a draft parser only
 * ever sees a document 1.0 has declined. Legacy entries are grouped so draft support can be
 * removed as a block.
 *
 * Every failure returns a [WrappedIssuerConfigResponse] carrying an `errorResponse` -- never a
 * bare null. Callers previously could not tell "no address given" from "network failure" from
 * "not an issuer", and the wallet's error branch never fired for the first of those.
 */
class IssuerMetadataResolver(
    private val policy: DiscoveryPolicy = DiscoveryPolicy.Default,
    private val validator: IssuerMetadataValidator = IssuerMetadataValidator(),
    private val parsers: List<IssuerMetadataParser> = defaultParsers(),
    private val signedMetadataVerifier: SignedMetadataVerifier = SignatureValidatorSignedMetadataVerifier(),
) {

    suspend fun resolve(input: String?): DiscoveredIssuerMetadata {
        val identifier = WellKnownUrlBuilder.identifier(input)
            ?: return failure(DiscoveryException.NoIdentifier(), IssuerMetadataDiagnostics(null))

        val scheme = WellKnownUrlBuilder.scheme(identifier)
        if (scheme.isNullOrBlank()) {
            return failure(
                DiscoveryException.InvalidIdentifier(identifier),
                IssuerMetadataDiagnostics(identifier),
            )
        }
        if (!policy.allowsScheme(scheme)) {
            return failure(
                DiscoveryException.UnsupportedScheme(scheme),
                IssuerMetadataDiagnostics(identifier),
            )
        }

        val candidates = WellKnownUrlBuilder.candidates(
            identifier,
            WellKnownUrlBuilder.OPENID_CREDENTIAL_ISSUER,
            policy,
        )
        if (candidates.isEmpty()) {
            return failure(
                DiscoveryException.InvalidIdentifier(identifier),
                IssuerMetadataDiagnostics(identifier),
            )
        }

        var mostInformative: DiscoveryException? = null

        // The two layouts coincide for an identifier with no path, in which case the single URL is
        // the spec form and is reported as such.
        val insertionUrl = WellKnownUrlBuilder.insertionForm(
            identifier,
            WellKnownUrlBuilder.OPENID_CREDENTIAL_ISSUER,
        )

        for ((index, url) in candidates.withIndex()) {
            val form = if (url == insertionUrl) WellKnownForm.Insertion else WellKnownForm.Suffix

            try {
                val document = MetadataFetcher.fetch(url, policy) { requestUrl ->
                    ApiManager.api.getService()?.fetchIssuerConfig(
                        requestUrl,
                        MetadataFetcher.acceptHeader(signedMetadataVerifier.supportsSignedMetadata),
                        MetadataFetcher.acceptLanguageHeader(policy),
                    )
                }

                val json = asJsonObject(document, identifier)
                val parser = selectParser(json)
                val config = validator.validate(parser.parse(json), parser.specVersion, identifier, policy)

                if (form == WellKnownForm.Suffix) {
                    Logger.d(TAG, "Issuer metadata came from the non-spec suffix URL: $url")
                }
                Logger.d(TAG, "Resolved ${parser.specVersion} issuer metadata for $identifier")

                return DiscoveredIssuerMetadata(
                    response = WrappedIssuerConfigResponse(issuerConfig = config),
                    diagnostics = IssuerMetadataDiagnostics(
                        identifier = identifier,
                        attemptedUrls = candidates.take(index + 1),
                        resolvedUrl = url,
                        form = form,
                        contentType = document.contentType,
                        specVersion = parser.specVersion,
                    ),
                )
            } catch (e: DiscoveryException) {
                mostInformative = mostInformative.orMoreInformativeThan(e)
            } catch (e: Exception) {
                Logger.e(TAG, "Unexpected failure resolving issuer metadata from $url", e)
                mostInformative = mostInformative.orMoreInformativeThan(
                    DiscoveryException.Malformed("The issuer configuration could not be read")
                )
            }
        }

        return failure(
            mostInformative ?: DiscoveryException.FetchFailed(null, null),
            IssuerMetadataDiagnostics(identifier = identifier, attemptedUrls = candidates),
        )
    }

    /**
     * A signed document reaches the verifier; anything else is parsed as JSON.
     *
     * The JWT check is on shape as well as media type: a JWT served as `application/json` must
     * still be verified, never decoded and trusted.
     */
    private suspend fun asJsonObject(document: MetadataDocument, identifier: String): JsonObject {
        val body = if (document.isJwtMediaType || MetadataFetcher.looksLikeJwt(document.body)) {
            signedMetadataVerifier.verify(document.body.trim(), identifier)
        } else {
            if (policy.requireJsonContentType && !document.isJsonMediaType) {
                throw DiscoveryException.NotJson(document.contentType)
            }
            document.body
        }

        val element = try {
            JsonParser.parseString(body)
        } catch (e: Exception) {
            throw DiscoveryException.Malformed("The issuer configuration was not valid JSON")
        }
        if (element == null || !element.isJsonObject) {
            throw DiscoveryException.Malformed("The issuer configuration was not valid JSON")
        }
        return element.asJsonObject
    }

    private fun selectParser(json: JsonObject): IssuerMetadataParser {
        val parser = parsers.firstOrNull { it.supports(json) }
            ?: throw DiscoveryException.Malformed(
                "This address did not return a recognisable issuer configuration"
            )
        if (parser.specVersion == IssuerMetadataSpecVersion.Draft && !policy.allowDraftMetadata) {
            throw DiscoveryException.Invalid(
                "This issuer publishes a pre-1.0 configuration, which is not accepted"
            )
        }
        return parser
    }

    private fun failure(
        error: DiscoveryException,
        diagnostics: IssuerMetadataDiagnostics,
    ): DiscoveredIssuerMetadata = DiscoveredIssuerMetadata(
        response = WrappedIssuerConfigResponse(
            issuerConfig = null,
            errorResponse = ErrorResponse(
                error = error.httpStatus,
                errorDescription = error.message,
            ),
        ),
        diagnostics = diagnostics,
    )

    companion object {
        private const val TAG = "IssuerMetadataResolver"

        /** OpenID4VCI 1.0 first; everything below the marker is deletable as a block. */
        fun defaultParsers(): List<IssuerMetadataParser> = listOf(
            OpenId4VciV1IssuerMetadataParser(),
            // --- legacy, safe to delete together ---
            DraftIssuerMetadataParser(),
        )
    }
}
