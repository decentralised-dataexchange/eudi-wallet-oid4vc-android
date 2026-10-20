package com.ewc.eudi_wallet_oidc_android.services.verification.request.legacy

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.ClientMetaDetails
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall.safeApiCallResponse
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.isValidJWT
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.parseJWTForPayload
import com.google.gson.Gson

/**
 * LEGACY, draft 20 and earlier: dereferences `client_metadata_uri`. OpenID4VP 1.0 only has
 * `client_metadata` by value. Delete this file and its call in the resolver to drop support.
 *
 * A fetch that fails is not fatal: the metadata only matters for an encrypted response, and a
 * verifier that asked for one without reachable keys fails at submission with its own message.
 */
class ClientMetadataUriResolver {

    suspend fun resolve(uri: String): ClientMetaDetails? {
        val result = try {
            safeApiCallResponse { ApiManager.api.getService()?.resolveUrl(uri) }
        } catch (e: Exception) {
            Logger.w(TAG, "client_metadata_uri could not be fetched: ${e.message}")
            return null
        }

        return result.fold(
            onSuccess = { response ->
                val contentType = response.headers()["Content-Type"]
                val body = response.body()?.string().orEmpty()
                try {
                    when {
                        contentType?.contains("application/json") == true ->
                            Gson().fromJson(body, ClientMetaDetails::class.java)
                        isValidJWT(body) ->
                            Gson().fromJson(parseJWTForPayload(body), ClientMetaDetails::class.java)
                        else ->
                            Gson().fromJson(body, ClientMetaDetails::class.java)
                    }
                } catch (e: Exception) {
                    Logger.w(TAG, "client_metadata_uri answered with something that is not client metadata")
                    null
                }
            },
            onFailure = { error ->
                Logger.w(TAG, "client_metadata_uri could not be fetched: ${error.message}")
                null
            },
        )
    }

    private companion object {
        const val TAG = "ClientMetadataUriResolver"
    }
}
