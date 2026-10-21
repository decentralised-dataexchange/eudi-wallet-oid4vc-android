package com.ewc.eudi_wallet_oidc_android.services.verification.response

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall.safeApiCallResponse
import com.ewc.eudi_wallet_oidc_android.services.utils.ErrorHandler
import com.google.gson.JsonParser
import java.net.URLDecoder

/**
 * OpenID4VP 1.0 section 8.2: the Authorization Response goes to the `response_uri` as an
 * `application/x-www-form-urlencoded` POST, and a verifier that processed it "MUST respond with
 * an HTTP status code of 200 with Content-Type of application/json and a JSON object in the
 * response body", optionally carrying `redirect_uri`. A 204 is taken as acceptance without a
 * redirect, and a 302 `Location` is read for the verifiers that answer with one.
 */
class DirectPostClient {

    suspend fun post(responseUri: String, fields: Map<String, String>, headers: Map<String, String>): PresentationOutcome {
        val result = safeApiCallResponse { ApiManager.api.getService()?.sendVPToken(responseUri, fields, headers) }
        return result.fold(
            onSuccess = { response ->
                val code = response.code()
                when {
                    code == 200 -> {
                        val body = response.body()?.string()
                        val json = try {
                            JsonParser.parseString(body).asJsonObject
                        } catch (e: Exception) {
                            null
                        }
                        fun field(name: String) = json?.get(name)?.takeIf { it.isJsonPrimitive }?.asString?.takeIf { it.isNotBlank() }
                        // `code` is what an issuer's interactive authorization endpoint answers
                        // a presentation with; a verifier's response URI sends `redirect_uri`.
                        PresentationOutcome.Accepted(redirectUri = field("redirect_uri"), authorizationCode = field("code"))
                    }
                    code == 204 -> PresentationOutcome.Accepted()
                    code in 300..399 -> {
                        val location = response.headers()["Location"]
                        val error = location?.let { errorIn(it) }
                        if (error != null) PresentationOutcome.Refused(error.apply { httpStatus = code })
                        else PresentationOutcome.Accepted(location = location)
                    }
                    else -> PresentationOutcome.Refused(refusal(response.errorBody()?.string(), code))
                }
            },
            onFailure = { error ->
                // SafeApiCall turns a 4xx or 5xx into a failure carrying the body, and a transport
                // failure into one carrying its message.
                PresentationOutcome.Refused(refusal(error.message, null))
            },
        )
    }

    private fun refusal(body: String?, status: Int?): ErrorResponse {
        val parsed = ErrorHandler.processError(body, status)
        return ErrorResponse(
            error = status ?: parsed?.error,
            errorDescription = parsed?.errorDescription?.takeIf { it.isNotBlank() } ?: body?.takeIf { it.isNotBlank() } ?: "The verifier did not accept the presentation",
            errorCode = parsed?.errorCode,
            errorUri = parsed?.errorUri,
            httpStatus = status,
            raw = body,
        ).also { Logger.d(TAG, "Presentation refused: ${it.errorCode ?: ""} ${it.errorDescription}") }
    }

    /** The OAuth error carried in a redirect's query or fragment, when there is one. */
    private fun errorIn(location: String): ErrorResponse? {
        val query = location.substringAfter('?', "").substringBefore('#').ifEmpty { location.substringAfter('#', "") }
        if (query.isBlank()) return null
        val params = query.split('&').mapNotNull { pair ->
            val key = pair.substringBefore('=')
            val value = pair.substringAfter('=', "")
            if (key.isBlank()) null else key to (try { URLDecoder.decode(value, "UTF-8") } catch (e: Exception) { value })
        }.toMap()
        val code = params["error"] ?: return null
        return ErrorResponse(
            error = if (code == "invalid_request") 400 else null,
            errorDescription = params["error_description"] ?: code,
            errorCode = code,
            errorUri = params["error_uri"],
        )
    }

    private companion object {
        const val TAG = "DirectPostClient"
    }
}
