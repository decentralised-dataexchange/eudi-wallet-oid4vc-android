package com.ewc.eudi_wallet_oidc_android.services.notification

import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.WrappedRefreshTokenResponse
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.NotificationRequest
import com.ewc.eudi_wallet_oidc_android.models.v2.DeferredCredentialRequestV2
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall

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
     */
    override suspend fun sendNotificationRequest(
        notificationEndPoint: String?,
        accessToken: String?,
        notificationId: String?,
        event: NotificationEventType
    ) {
        // Validate input values before making the API call
        if (notificationEndPoint.isNullOrEmpty() || accessToken.isNullOrEmpty() ||
            notificationId.isNullOrEmpty()) {
            Log.e("sendNotificationRequest", "Invalid input parameters, request aborted.")
            return // Exit early if any input is missing
        }
        Log.d("sendNotificationRequest", "Endpoint: $notificationEndPoint")
        Log.d("sendNotificationRequest", "Authorization: Bearer $accessToken")
        Log.d("sendNotificationRequest", "Event: ${event.value}")
        Log.d("sendNotificationRequest", "NotificationId: $notificationId")

        // Use safeApiCallResponse wrapper
        val result = SafeApiCall.safeApiCallResponse {
            ApiManager.api.getService()?.sendNotificationRequest(
                notificationEndPoint,
                "Bearer $accessToken",
                NotificationRequest(notificationId, event.value)
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