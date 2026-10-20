package com.ewc.eudi_wallet_oidc_android.services.verification.request.source

import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.request.AuthorizationRequestUri
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestException
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestPolicy
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.google.gson.JsonParser

/**
 * The parameters travel in the request URI itself: `?client_id=...&dcql_query=<JSON>&...`.
 *
 * OpenID4VP 1.0 section 5. Recognised by the query parameter: `dcql_query` for 1.0, or the draft
 * `presentation_definition` and `presentation_definition_uri`, which the resolver quarantines.
 */
class InlinePresentationRequestSource : PresentationRequestSource {

    override val name: String = "by_value"

    override fun supports(data: String): Boolean =
        QUERY_PARAMS.any { AuthorizationRequestUri.hasQueryParam(data, it) }

    override suspend fun retrieve(data: String, policy: PresentationRequestPolicy): PresentationRequest {
        fun param(name: String) = AuthorizationRequestUri.queryParam(data, name)

        val clientMetadata: JsonObject? = param("client_metadata")?.takeIf { it.isNotBlank() }?.let {
            try {
                JsonParser.parseString(it).asJsonObject
            } catch (e: Exception) {
                throw PresentationRequestException.Malformed("Invalid Request: client_metadata is not a JSON object")
            }
        }

        val dcqlQuery: DCQL? = try {
            param("dcql_query")?.takeIf { it.isNotBlank() }?.let { Gson().fromJson(it, DCQL::class.java) }
        } catch (e: Exception) {
            // Malformed JSON, or a member of the wrong type (for example "credentials" as an
            // object): refused the same way as a structurally invalid query.
            throw PresentationRequestException.InvalidDcqlQuery(e.message)
        }

        // Section 5.1: a non-empty JSON array of base64url strings. Unreadable values are kept as
        // they are so the transaction data check refuses them instead of them vanishing here.
        val transactionData: ArrayList<String>? = param("transaction_data")?.takeIf { it.isNotBlank() }?.let { value ->
            try {
                ArrayList(JsonParser.parseString(value).asJsonArray.map { it.asString })
            } catch (e: Exception) {
                arrayListOf(value)
            }
        }

        return PresentationRequest(
            clientId = param("client_id"),
            state = param("state"),
            redirectUri = param("redirect_uri"),
            nonce = param("nonce"),
            presentationDefinition = param("presentation_definition"),
            presentationDefinitionUri = param("presentation_definition_uri"),
            responseMode = param("response_mode"),
            responseType = param("response_type"),
            scope = param("scope"),
            requestUri = param("request_uri"),
            responseUri = param("response_uri"),
            clientMetaDetails = clientMetadata,
            clientMetadataUri = param("client_metadata_uri"),
            clientIdScheme = param("client_id_scheme"),
            request = param("request"),
            dcqlQuery = dcqlQuery,
            transactionDdata = transactionData,
        )
    }

    private companion object {
        val QUERY_PARAMS = listOf("dcql_query", "presentation_definition", "presentation_definition_uri")
    }
}
