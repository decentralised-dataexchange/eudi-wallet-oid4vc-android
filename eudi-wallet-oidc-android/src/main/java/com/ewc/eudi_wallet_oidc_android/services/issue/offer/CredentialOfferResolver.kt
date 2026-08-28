package com.ewc.eudi_wallet_oidc_android.services.issue.offer

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedCredentialOffer
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.parser.CredentialOfferParser
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.parser.OpenId4VciV1OfferParser
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.parser.legacy.EbsiDraftOfferParser
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.parser.legacy.EwcDraftOfferParser
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.source.CredentialOfferSource
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.source.InlineCredentialOfferSource
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.source.RemoteCredentialOfferSource
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.source.legacy.InitiateIssuanceOfferSource
import com.google.gson.JsonObject
import com.google.gson.JsonParser

/**
 * Resolves scanned data into a credential offer: pick a source, retrieve the document, pick a
 * parser, validate.
 *
 * Both registries are ordered, and OpenID4VCI 1.0 always comes first. Legacy entries are grouped
 * so draft support can be removed as a block.
 *
 * Every failure returns a [WrappedCredentialOffer] carrying an `errorResponse` -- never a bare
 * null, and never an empty wrapper. Callers previously could not distinguish "not an offer" from
 * "malformed offer" from "network failure", and the wallet's error branch never fired.
 */
class CredentialOfferResolver(
    private val policy: CredentialOfferPolicy = CredentialOfferPolicy.Default,
    private val validator: CredentialOfferValidator = CredentialOfferValidator(),
    private val sources: List<CredentialOfferSource> = defaultSources(),
    private val parsers: List<CredentialOfferParser> = defaultParsers(),
) {

    suspend fun resolve(data: String?): WrappedCredentialOffer {
        if (data.isNullOrBlank()) return failure(CredentialOfferException.NoOffer())

        return try {
            val document = retrieve(data)
            val json = asJsonObject(document)
            val parser = selectParser(json)

            val offer = validator.validate(parser.parse(json), parser.specVersion)
            offer.version = parser.specVersion.legacyVersionCode

            Logger.d(TAG, "Resolved a ${parser.specVersion} credential offer")
            WrappedCredentialOffer(credentialOffer = offer)
        } catch (e: CredentialOfferException) {
            failure(e)
        } catch (e: Exception) {
            // Nothing below should throw anything else; if it does, the user still gets a message.
            Logger.e(TAG, "Unexpected failure resolving a credential offer", e)
            failure(CredentialOfferException.Malformed("The credential offer could not be read"))
        }
    }

    private suspend fun retrieve(data: String): String {
        val matching = sources.filter { it.supports(data) }

        // The spec forbids carrying both credential_offer and credential_offer_uri.
        if (matching.size > 1 && policy.rejectAmbiguousOffers) {
            throw CredentialOfferException.AmbiguousOffer()
        }
        val source = matching.firstOrNull() ?: throw CredentialOfferException.NoOffer()
        return source.retrieve(data, policy)
    }

    private fun asJsonObject(document: String): JsonObject {
        val trimmed = document.trim()
        if (looksLikeJwt(trimmed)) throw CredentialOfferException.SignedOfferRejected()

        val element = try {
            JsonParser.parseString(trimmed)
        } catch (e: Exception) {
            throw CredentialOfferException.Malformed("The credential offer is not valid JSON")
        }
        if (!element.isJsonObject) {
            throw CredentialOfferException.Malformed("The credential offer is not valid JSON")
        }
        return element.asJsonObject
    }

    private fun selectParser(json: JsonObject): CredentialOfferParser {
        val parser = parsers.firstOrNull { candidate ->
            if (candidate.specVersion == CredentialOfferSpecVersion.Draft && !policy.allowDraftOffers) {
                false
            } else {
                candidate.supports(json)
            }
        }
        return parser ?: throw CredentialOfferException.Malformed(
            "This credential offer is not in a supported format"
        )
    }

    /** Three dot-separated base64url segments, i.e. a compact JWS. */
    private fun looksLikeJwt(document: String): Boolean {
        if (document.startsWith("{") || document.startsWith("[")) return false
        val parts = document.split('.')
        return parts.size == 3 && parts.all { part ->
            part.isNotEmpty() && part.all { it.isLetterOrDigit() || it == '-' || it == '_' }
        }
    }

    private fun failure(e: CredentialOfferException): WrappedCredentialOffer {
        Logger.d(TAG, "Credential offer rejected: ${e.message}")
        return WrappedCredentialOffer(
            credentialOffer = null,
            errorResponse = ErrorResponse(error = -1, errorDescription = e.message),
        )
    }

    companion object {
        private const val TAG = "CredentialOfferResolver"

        /** Ordered: 1.0 mechanisms first, legacy last. */
        fun defaultSources(): List<CredentialOfferSource> = listOf(
            InlineCredentialOfferSource(),
            RemoteCredentialOfferSource(),
            // --- legacy, safe to delete as a block ---
            InitiateIssuanceOfferSource(),
        )

        /** Ordered: 1.0 first, so a draft parser only sees what 1.0 declined. */
        fun defaultParsers(): List<CredentialOfferParser> = listOf(
            OpenId4VciV1OfferParser(),
            // --- legacy, safe to delete as a block ---
            EbsiDraftOfferParser(),
            EwcDraftOfferParser(),
        )
    }
}
