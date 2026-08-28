package com.ewc.eudi_wallet_oidc_android.services.issue.offer.source

import com.ewc.eudi_wallet_oidc_android.services.issue.offer.CredentialOfferException
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.CredentialOfferPolicy
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.OfferUri
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall

/**
 * The link points at the offer: `?credential_offer_uri=<https URL>`.
 *
 * OpenID4VCI 1.0 section 4.1: the wallet MUST fetch it with an HTTP GET, the response media type
 * MUST be `application/json`, and the offer cannot be signed.
 */
class RemoteCredentialOfferSource : CredentialOfferSource {

    override val name: String = "credential_offer_uri"

    override fun supports(data: String): Boolean =
        !OfferUri.queryParam(data, PARAM).isNullOrBlank()

    override suspend fun retrieve(data: String, policy: CredentialOfferPolicy): String {
        val uri = OfferUri.queryParam(data, PARAM)
        if (uri.isNullOrBlank()) throw CredentialOfferException.NoOffer()

        val scheme = OfferUri.scheme(uri)
        if (!policy.allowsScheme(scheme)) throw CredentialOfferException.UnsupportedScheme(scheme)

        val result = SafeApiCall.safeApiCallResponse {
            ApiManager.api.getService()?.fetchCredentialOffer(uri)
        }

        return result.fold(
            onSuccess = { response ->
                // A 3xx reaches here because SafeApiCall treats redirects as success, and the
                // client does not follow them.
                if (!response.isSuccessful) {
                    throw CredentialOfferException.FetchFailed(
                        httpStatus = response.code(),
                        detail = "The issuer redirected the credential offer request",
                    )
                }

                val contentType = response.headers()["Content-Type"]
                if (policy.requireJsonContentType && !isJson(contentType)) {
                    throw CredentialOfferException.NotJson(contentType)
                }
                if (isJwt(contentType)) throw CredentialOfferException.SignedOfferRejected()

                val body = response.body()
                val declaredLength = body?.contentLength() ?: -1L
                if (declaredLength > policy.maxOfferBytes) {
                    throw CredentialOfferException.TooLarge(declaredLength)
                }

                val text = body?.string().orEmpty()
                if (text.length > policy.maxOfferBytes) {
                    throw CredentialOfferException.TooLarge(text.length.toLong())
                }
                if (text.isBlank()) {
                    throw CredentialOfferException.FetchFailed(response.code(), "The credential offer was empty")
                }
                text
            },
            onFailure = { error ->
                // SafeApiCall has already turned any 4xx/5xx into a failure carrying the response
                // body, so the HTTP status is not recoverable here.
                throw CredentialOfferException.FetchFailed(httpStatus = null, detail = error.message)
            },
        )
    }

    private fun isJson(contentType: String?): Boolean =
        contentType?.substringBefore(';')?.trim()?.lowercase()
            ?.let { it == "application/json" || it.endsWith("+json") } == true

    private fun isJwt(contentType: String?): Boolean =
        contentType?.substringBefore(';')?.trim()?.lowercase() == "application/jwt"

    private companion object {
        const val PARAM = "credential_offer_uri"
    }
}
