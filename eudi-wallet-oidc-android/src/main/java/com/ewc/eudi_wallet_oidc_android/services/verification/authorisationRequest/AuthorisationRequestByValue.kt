package com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest

import android.net.Uri
import com.ewc.eudi_wallet_oidc_android.models.ClientMetaDetails
import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest.ProcessPresentationRequestWithUris.processPresentationRequest
import com.google.gson.Gson

/**
 * Handles the processing of authorization requests by value, as described in
 * [EWC-RFC002 Section 3.1.3: Passing the Request](https://github.com/EWC-consortium/eudi-wallet-rfcs/blob/main/ewc-rfc002-present-verifiable-credentials.md#313-passing-the-request).
 *
 * This class parses the authorization request parameters from a URI, constructs a
 * `PresentationRequest` object, and delegates further processing. It supports all
 * parameters defined in the RFC, including `client_id`, `state`, `redirect_uri`,
 * `nonce`, `presentation_definition`, `presentation_definition_uri`, and others.
 */
class AuthorisationRequestByValue : AuthorisationRequestHandler {

    override suspend fun processAuthorisationRequest(
        authorisationRequestData: String
    ): WrappedPresentationRequest {
        val uri = Uri.parse(authorisationRequestData)
        val gson = Gson()
        val clientId = uri.getQueryParameter("client_id")
        val state = uri.getQueryParameter("state")
        val redirectUri = uri.getQueryParameter("redirect_uri")
        val nonce = uri.getQueryParameter("nonce")
        val presentationDefinition = uri.getQueryParameter("presentation_definition")
        val presentationDefinitionUri = uri.getQueryParameter("presentation_definition_uri")

        val responseType = uri.getQueryParameter("response_type")
        val scope = uri.getQueryParameter("scope")
        val requestUri = uri.getQueryParameter("request_uri")
        val responseUri = uri.getQueryParameter("response_uri")
        val responseMode = uri.getQueryParameter("response_mode")
        val clientMetadataUri = uri.getQueryParameter("client_metadata_uri")
        val clientMetadataJson = uri.getQueryParameter("client_metadata")
        val clientIdScheme = uri.getQueryParameter("client_id_scheme")
        val clientMetadetails: ClientMetaDetails? = if (!clientMetadataJson.isNullOrBlank()) {
            gson.fromJson(clientMetadataJson, ClientMetaDetails::class.java)
        } else {
            null
        }
        val request = uri.getQueryParameter("request")
        val dcqlQueryJson = uri.getQueryParameter("dcql_query")
        val dcqlQuery: DCQL? = dcqlQueryJson
            ?.takeIf { it.isNotBlank() }
            ?.let { gson.fromJson(it, DCQL::class.java) }

        val presentationRequest = PresentationRequest(
            clientId = clientId,
            state = state,
            redirectUri = redirectUri,
            nonce = nonce,
            presentationDefinition = presentationDefinition,
            presentationDefinitionUri = presentationDefinitionUri,
            responseMode = responseMode,
            responseType = responseType,
            scope = scope,
            requestUri = requestUri,
            responseUri = responseUri,
            clientMetaDetails = clientMetadetails,
            clientMetadataUri = clientMetadataUri,
            clientIdScheme = clientIdScheme,
            request = request,
            dcqlQuery = dcqlQuery
        )
        return processPresentationRequest(presentationRequest)
    }
}