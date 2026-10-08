package com.ewc.eudi_wallet_oidc_android.services.notification

import android.util.Log
import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.WrappedRefreshTokenResponse
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.NotificationRequest
import com.ewc.eudi_wallet_oidc_android.models.v2.DeferredCredentialRequestV2
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall
import com.ewc.eudi_wallet_oidc_android.services.utils.DPoPProofService
import com.nimbusds.jose.jwk.ECKey

class NotificationService : NotificationServiceInterface {

    /**
     * Sends a notification request to the Issuer's notification endpoint.
     *
     * This method implements the notification mechanism as specified in EWC-RFC001 Section 6.1.4.
     * It notifies the Issuer about the status of credential operations through a POST request.
     *
     * @param notificationEndPoint The URL of the Issuer's notification endpoint
     * @param accessToken The OAuth 2.0 access token for authentication
     * @param notificationId received in the Credential/Deferred Response.
     * @param event The type of event being notified (accepted/deleted/failure)
     * @param dpopKey The key the access token is DPoP-bound to (cnf.jkt). When provided, a DPoP
     *                proof (htm/htu/ath) is sent and the Authorization scheme is "DPoP"; when null
     *                the request is sent as a Bearer request, as before.
     */
    override suspend fun sendNotificationRequest(
        notificationEndPoint: String?,
        accessToken: String?,
        notificationId: String?,
        event: NotificationEventType,
        dpopKey: ECKey?
    ) {
        // Validate input values before making the API call
        if (notificationEndPoint.isNullOrEmpty() || accessToken.isNullOrEmpty() ||
            notificationId.isNullOrEmpty()) {
            Log.e("sendNotificationRequest", "Invalid input parameters, request aborted.")
            return // Exit early if any input is missing
        }
        Logger.d("sendNotificationRequest", "Endpoint: $notificationEndPoint")
        // The token itself is never logged; Logger.networkInterceptor redacts the header too.
        Logger.d("sendNotificationRequest", "Authorization: Bearer <redacted>")
        Logger.d("sendNotificationRequest", "Event: ${event.value}")
        Logger.d("sendNotificationRequest", "NotificationId: $notificationId")

        val dpopProof = if (dpopKey != null) {
            DPoPProofService().generateDPoP(
                httpMethod = "POST",
                targetUri = notificationEndPoint,
                dpopKey = dpopKey,
                claims = mapOf("ath" to DPoPProofService().computeAccessTokenHash(accessToken))
            )
        } else null
        val authHeader = if (dpopProof != null) "DPoP $accessToken" else "Bearer $accessToken"

        // Use safeApiCallResponse wrapper
        val result = SafeApiCall.safeApiCallResponse {
            ApiManager.api.getService()?.sendNotificationRequest(
                notificationEndPoint,
                authHeader,
                NotificationRequest(notificationId, event.value),
                dpopProof
            )
        }

        result.onSuccess { response ->
            when {
                response.code() == 204 -> {
                    Log.d("sendNotificationResponse", "Request successful, but no content (204).")
                }
                response.code() >= 400 -> {
                    val errorBody = try {
                        response.errorBody()?.string() ?: "Unknown error"
                    } catch (e: Exception) {
                        "Error reading errorBody: ${e.message}"
                    }
                    Log.e("sendNotificationResponse", "Error: $errorBody")
                }
                else -> {
                    Log.d("sendNotificationResponse", "Request successful: ${response.code()}")
                }
            }
        }.onFailure { e ->
            Log.e("sendNotificationRequest", "Exception while sending notification: ${e.message}")
        }
    }

}