package com.ewc.eudi_wallet_oidc_android.services.verification.request.legacy

import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall.safeApiCallResponse
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.isValidJWT
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.parseJWTForPayload
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestException
import com.google.gson.Gson

/**
 * LEGACY, draft 20 and earlier: dereferences `presentation_definition_uri`. OpenID4VP 1.0 has no
 * such parameter. Delete this file and its call in the resolver to drop support.
 *
 * A fetch that fails is a failure of the whole request: a presentation definition request with
 * no definition cannot be matched against anything, so resolving it would only move the error to
 * a later step where its cause is lost.
 */
class PresentationDefinitionUriResolver {

    /**
     * @throws PresentationRequestException.PresentationDefinitionUnavailable
     */
    suspend fun resolve(uri: String): PresentationDefinition {
        val result = try {
            safeApiCallResponse { ApiManager.api.getService()?.resolveUrl(uri) }
        } catch (e: Exception) {
            throw PresentationRequestException.PresentationDefinitionUnavailable(e.message)
        }

        return result.fold(
            onSuccess = { response ->
                val contentType = response.headers()["Content-Type"]
                val body = response.body()?.string().orEmpty()
                val parsed = try {
                    when {
                        contentType?.contains("application/json") == true ->
                            Gson().fromJson(body, PresentationDefinition::class.java)
                        isValidJWT(body) ->
                            Gson().fromJson(parseJWTForPayload(body), PresentationDefinition::class.java)
                        else ->
                            Gson().fromJson(body, PresentationDefinition::class.java)
                    }
                } catch (e: Exception) {
                    null
                }
                parsed ?: throw PresentationRequestException.PresentationDefinitionUnavailable(
                    "the response was not a presentation definition"
                )
            },
            onFailure = { error ->
                throw PresentationRequestException.PresentationDefinitionUnavailable(error.message)
            },
        )
    }
}
