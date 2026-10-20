package com.ewc.eudi_wallet_oidc_android.services.verification.request.source

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall.safeApiCallResponse
import com.ewc.eudi_wallet_oidc_android.services.verification.request.AuthorizationRequestUri
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestException
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestPolicy
import com.ewc.eudi_wallet_oidc_android.services.verification.request.RequestObjectParser
import com.ewc.eudi_wallet_oidc_android.services.verification.request.RequestUriMethod
import com.google.gson.Gson

/**
 * The request object sits behind a `request_uri`.
 *
 * RFC 9101 section 5.2 fetches it with a GET. OpenID4VP 1.0 section 5.10 adds
 * `request_uri_method=post`: a form POST carrying the wallet's metadata and a fresh `wallet_nonce`
 * that the verifier MUST echo in the request object, which MAY come back encrypted to the key the
 * wallet sent. Section 5.10.2: any HTTP error from the verifier terminates the process.
 */
class RemotePresentationRequestSource : PresentationRequestSource {

    override val name: String = "request_uri"

    override fun supports(data: String): Boolean = RequestUriMethod.requestUri(data) != null

    override suspend fun retrieve(data: String, policy: PresentationRequestPolicy): PresentationRequest {
        val requestUri = RequestUriMethod.requestUri(data) ?: throw PresentationRequestException.NoRequest()
        val clientIdFromUri = AuthorizationRequestUri.queryParam(data, "client_id")

        // Anything other than request_uri_method=post is the plain GET of RFC 9101.
        val walletNonce = if (RequestUriMethod.isPost(data)) RequestUriMethod.newWalletNonce() else null
        val encryptionKey = if (walletNonce != null) RequestUriMethod.newEncryptionKey() else null

        val result = safeApiCallResponse {
            val service = ApiManager.api.getService()
            if (walletNonce != null) {
                service?.postPresentationRequestToRequestUri(
                    requestUri,
                    mapOf(
                        RequestUriMethod.WALLET_METADATA to RequestUriMethod.walletMetadata(encryptionKey),
                        RequestUriMethod.WALLET_NONCE to walletNonce
                    ),
                    RequestUriMethod.REQUEST_OBJECT_MEDIA_TYPE
                )
            } else {
                service?.getPresentationDefinitionFromRequestUri(requestUri)
            }
        }

        val rawBody = result.fold(
            onSuccess = { response -> response.body()?.string() },
            onFailure = { error -> throw PresentationRequestException.FetchFailed(error.message) },
        )

        // A verifier given our key may answer with an encrypted request object; open it here so
        // the rest of the handling sees the signed request JWT as usual.
        val body = if (rawBody != null && encryptionKey != null) {
            RequestUriMethod.unwrapEncrypted(rawBody, encryptionKey) ?: throw PresentationRequestException.NonceMismatch()
        } else rawBody
        if (body.isNullOrBlank()) throw PresentationRequestException.EmptyResponse()

        val request = parseJson(body)?.also {
            // Not in OpenID4VP 1.0, which requires a request object (section 5.10.1). Kept for
            // the verifiers that answer with the bare parameters.
            Logger.w(TAG, "request_uri answered with plain JSON instead of a request object")
        } ?: parseRequestObject(body, policy)

        // Section 5.10.1: a request object fetched by POST MUST carry the wallet_nonce it was
        // asked for; without it the request is dropped.
        if (!RequestUriMethod.nonceAccepted(walletNonce, request.walletNonce)) {
            throw PresentationRequestException.NonceMismatch()
        }
        RequestObjectParser.requireMatchingClientId(clientIdFromUri, request)
        return request
    }

    private fun parseJson(body: String): PresentationRequest? {
        if (!body.trimStart().startsWith("{")) return null
        return try {
            Gson().fromJson(body, PresentationRequest::class.java)
        } catch (e: Exception) {
            null
        }
    }

    private fun parseRequestObject(body: String, policy: PresentationRequestPolicy): PresentationRequest {
        if (!RequestObjectParser.looksLikeJwt(body)) throw PresentationRequestException.Malformed()
        val request = RequestObjectParser.parse(body)
        RequestObjectParser.requireSignedUnlessRedirectUri(body, request, policy)
        return request
    }

    private companion object {
        const val TAG = "RemotePresentationRequestSource"
    }
}
