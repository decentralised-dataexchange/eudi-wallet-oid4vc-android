package com.ewc.eudi_wallet_oidc_android.services.issue.notification

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletAttestation
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.HttpCall
import com.ewc.eudi_wallet_oidc_android.services.utils.DPoPProofService
import com.ewc.eudi_wallet_oidc_android.services.utils.ErrorHandler
import com.google.gson.Gson
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.ResponseBody
import retrofit2.Response

/**
 * Tells the issuer what happened to a credential it issued (section 11).
 *
 * Mirrors `NotificationRequestResolver` in the iOS SDK.
 */
class NotificationRequestResolver {

    suspend fun resolve(
        session: IssuanceSession,
        token: TokenResponse,
        notificationId: String,
        event: NotificationEvent,
        eventDescription: String? = null,
        attestation: WalletAttestation? = null,
        dpopNonce: String? = null,
    ): NotificationOutcome {
        val endpoint = session.issuerConfig?.notificationEndpoint
        if (endpoint.isNullOrBlank()) {
            // Section 11: the endpoint is optional, so its absence is not an error -- but the
            // caller should know nothing was sent rather than assume it was.
            return failed("This issuer published no notification endpoint")
        }
        if (notificationId.isBlank()) {
            return failed("The credential response carried no notification_id")
        }

        val accessToken = token.accessToken.orEmpty()
        val dpop = attestation?.dpopKey?.let {
            DPoPProofService().generateDPoP(
                httpMethod = "POST",
                targetUri = endpoint,
                dpopKey = it,
                claims = buildMap {
                    put("ath", DPoPProofService().computeAccessTokenHash(accessToken))
                    dpopNonce?.let { value -> put("nonce", value) }
                },
            )
        }
        val authorization = if (dpop != null) "DPoP $accessToken" else "Bearer $accessToken"

        val parameters = NotificationRequestParameters.build(notificationId, event, eventDescription)
        Logger.d(TAG, "notification: endpoint=$endpoint event=${event.value} id=$notificationId")

        return try {
            val response: Response<ResponseBody> = HttpCall.call(::notificationTransportFailure) {
                val body = Gson().toJson(parameters).toRequestBody("application/json".toMediaType())
                ApiManager.api.getService()?.sendNotification(endpoint, authorization, dpop, body)
            }

            // Section 11.2: 204 No Content is the success. Anything else 2xx is accepted too --
            // some issuers answer 200 with an empty body.
            if (response.isSuccessful) {
                Logger.d(TAG, "notification acknowledged (${response.code()})")
                return NotificationOutcome.Acknowledged
            }

            val body = HttpCall.errorBody(response)
            val error = ErrorHandler.processError(body, response.code())
            Logger.e(
                TAG,
                "notification refused ${response.code()} error=${error?.errorCode ?: error?.errorDescription}",
            )
            NotificationOutcome.Failed(
                error ?: ErrorResponse(
                    error = -1,
                    errorDescription = "The notification was refused (HTTP ${response.code()})",
                    httpStatus = response.code(),
                    raw = body,
                )
            )
        } catch (e: Exception) {
            Logger.e(TAG, "notification failed: ${e.message}")
            failed(e.message ?: "The notification request failed")
        }
    }

    private fun failed(reason: String) = NotificationOutcome.Failed(
        ErrorResponse(error = -1, errorDescription = reason)
    )

    private companion object {
        const val TAG = "NotificationRequest"
    }
}

/** @see com.ewc.eudi_wallet_oidc_android.services.network.HttpCall */
internal fun notificationTransportFailure(detail: String?): Exception =
    Exception(detail?.takeIf { it.isNotBlank() } ?: "The notification request failed")
