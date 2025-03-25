package com.ewc.eudi_wallet_oidc_android.services.notification

import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.WrappedRefreshTokenResponse
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.NotificationRequest
import com.ewc.eudi_wallet_oidc_android.models.v2.DeferredCredentialRequestV2
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager

class NotificationService : NotificationServiceInterface {
    override suspend fun processRefreshTokenRequest(
        tokenEndPoint: String?,
        refreshToken: String?
    ): WrappedRefreshTokenResponse? {
        val response = ApiManager.api.getService()?.getRefreshTokenFromCode(
            tokenEndPoint ?: "",
            if (refreshToken !=null){
                println("refreshToken is not null and generating new accessToken")
                mutableMapOf(
                    "grant_type" to "refresh_token",
                    "refresh_token" to (refreshToken),
                )
            }
            else {
                mutableMapOf(
                    "grant_type" to null,
                    "refresh_token" to (null),
                )
            },
        )

        val tokenResponse = when {
            response?.isSuccessful == true -> {
                WrappedRefreshTokenResponse(
                    tokenResponse = response.body()
                )
            }

            (response?.code() ?: 0) >= 400 -> {
                try {
                    WrappedRefreshTokenResponse(
                        errorResponse = ErrorResponse(error = null, errorDescription = response?.errorBody().toString())
                    )
                } catch (e: Exception) {
                    null
                }
            }

            else -> {
                null
            }
        }
        return tokenResponse
    }

    override suspend fun sendNotificationRequest(
        notificationEndPoint: String?,
        accessToken: String?,
        notificationId: String?,
        event: String?
    ) {
        // Validate input values before making the API call
        if (notificationEndPoint.isNullOrEmpty() || accessToken.isNullOrEmpty() ||
            notificationId.isNullOrEmpty() || event.isNullOrEmpty()) {
            Log.e("sendNotificationRequest", "Invalid input parameters, request aborted.")
            return // Exit early if any input is missing
        }
        Log.d("sendNotificationRequest", "Endpoint: $notificationEndPoint")
        Log.d("sendNotificationRequest", "Authorization: Bearer $accessToken")
        Log.d("sendNotificationRequest", "Event: $event")
        Log.d("sendNotificationRequest", "NotificationId: $notificationId")
        val response = ApiManager.api.getService()?.sendNotificationRequest(
            notificationEndPoint,
            "Bearer $accessToken",
            NotificationRequest(notificationId, event)
        )

        // If response code is 204, exit the function
        if (response?.code() == 204) {
            Log.d("sendNotificationResponse", "Request successful, but no content (204).")
            return
        }

        // Handle error responses (400 and above)
        if ((response?.code() ?: 0) >= 400) {
            try {
                val errorBody = response?.errorBody()?.string() ?: "Unknown error"
                Log.e("sendNotificationResponse", "Error: $errorBody")
            } catch (e: Exception) {
                Log.e("sendNotificationResponse", "Exception while logging error: ${e.message}")
            }
        }
    }

}