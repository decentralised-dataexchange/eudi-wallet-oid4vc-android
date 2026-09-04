package com.ewc.eudi_wallet_oidc_android.services.utils

import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

object ErrorHandler {

    /**
     * Turns whatever a server sent into an [ErrorResponse].
     *
     * The description logic below is unchanged and deliberately so — issuers send at least five
     * different shapes and each branch exists because one of them was met in the field. What is
     * new is that the OAuth `error` **code** now survives alongside the description instead of
     * being overwritten by it: a standard
     * `{"error":"invalid_grant","error_description":"Issuer state is not found"}` used to come back
     * as the sentence alone, leaving callers to string-match prose to decide what to do.
     */
    @Suppress("TooGenericExceptionCaught")
    @JvmOverloads
    fun processError(err: String?, httpStatus: Int? = null): ErrorResponse? {
        // Known possibilities for error:
        // 1. "Validation is failed"
        // 2. {"error_description": "Validation is failed", }
        // 3. {"errors": [{ "message": "Validation is failed" }]}
        // 4. {"error": "Validation is failed"}
        // 5. {"detail": "VC token expired"}
        val jsonObject = try {
            err?.let { JSONObject(it) }
        } catch (e: Exception) {
            null
        }
        // Read the code and the description as the two separate fields they are. `error` is only
        // a code when it is a string: some issuers nest the real pair under `detail`.
        val oauthCode = jsonObject?.let { root ->
            (root.opt("error") as? String)?.takeIf { it.isNotBlank() }
                ?: (root.opt("detail") as? JSONObject)
                    ?.let { it.opt("error") as? String }?.takeIf { it.isNotBlank() }
        }
        val errorUri = jsonObject?.let { (it.opt("error_uri") as? String)?.takeIf(String::isNotBlank) }

        val result = try {
        val errorResponse = when {
            err?.contains(
                "Invalid Proof JWT: iss doesn't match the expected client_id",
                true
            ) == true -> {
                ErrorResponse(error = 1, errorDescription = "DID is invalid")
            }

            jsonObject?.has("error_description") == true -> {
                ErrorResponse(
                    error = -1,
                    errorDescription = jsonObject.getString("error_description")
                )
            }

            jsonObject?.has("errors") == true -> {
                    val errorsValue = jsonObject.get("errors")
                    val errorDescription = when (errorsValue) {
                        is JSONArray -> errorsValue.getJSONObject(0).getString("message")
                        is JSONObject -> {
                            val firstKey = errorsValue.keys().next()
                            val firstValue = errorsValue.get(firstKey)
                            when (firstValue) {
                                is JSONArray -> "$firstKey: ${firstValue.optString(0)}"
                                else -> "$firstKey: $firstValue"
                            }
                        }
                        else -> errorsValue.toString()
                    }
                ErrorResponse(
                    error = -1,
                    errorDescription = errorDescription
                )
            }

            jsonObject?.has("error") == true -> {
                ErrorResponse(
                    error = -1,
                    errorDescription = jsonObject.getString("error")
                )
            }
            jsonObject?.has("detail") == true -> {
                val detailValue = jsonObject.get("detail")
                if (detailValue is JSONObject) {
                    // If "detail" is a nested JSON object, extract error_description or error
                    val detailJson = detailValue
                    val detailErrorDescription = detailJson.optString("error_description")
                    val detailError = detailJson.optString("error")
                    val description = when {
                        detailErrorDescription.isNotEmpty() -> detailErrorDescription
                        detailError.isNotEmpty() -> detailError
                        else -> detailJson.toString()
                    }
                    ErrorResponse(
                        error = -1,
                        errorDescription = description
                    )
                } else {
                    // If "detail" is a string or something else
                    ErrorResponse(
                        error = -1,
                        errorDescription = detailValue.toString()
                    )
                }
            }
            err?.contains("<html", ignoreCase = true) == true -> {
                ErrorResponse(
                    error = -1,
                    errorDescription = "Unexpected error, please try again."
                )
            }
//            jsonObject?.has("detail") == true -> {
//                ErrorResponse(
//                    error = -1,
//                    errorDescription = jsonObject.getString("detail")
//                )
//            }
            jsonObject?.has("message") == true -> {
                ErrorResponse(
                    error = -1,
                    errorDescription = jsonObject.getString("message")
                )
            }

            jsonObject != null -> {
                val firstKey = jsonObject.keys().next()
                val firstValue = jsonObject.get(firstKey)
                val description = when (firstValue) {
                    is JSONArray -> "$firstKey: ${firstValue.optString(0)}"
                    else -> "$firstKey: $firstValue"
                }
                ErrorResponse(error = -1, errorDescription = description)
            }

            else -> {
                ErrorResponse(
                    error = -1,
                    errorDescription = err
                )
            }
        }
            errorResponse
    } catch (e: JSONException) {
            Log.e("ErrorHandler", "Failed to parse error body: $err", e)
            ErrorResponse(error = -1, errorDescription = err)
    } catch (e: NoSuchElementException) {
            Log.e("ErrorHandler", "Failed to parse error body: $err", e)
            ErrorResponse(error = -1, errorDescription = err)
    } catch (e: Exception) {
            Log.e("ErrorHandler", "Error processing error response: ${e.message}")
            // Fallback: if any parsing step throws unexpectedly, return raw string
            ErrorResponse(error = -1, errorDescription = err)
        }

        return result?.apply {
            errorCode = oauthCode
            this.errorUri = errorUri
            this.httpStatus = httpStatus
            raw = err
        }
    }
}