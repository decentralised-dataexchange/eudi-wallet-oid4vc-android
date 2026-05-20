package com.ewc.eudi_wallet_oidc_android.services.utils

import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

object ErrorHandler {
    @Suppress("TooGenericExceptionCaught")
    fun processError(err: String?): ErrorResponse? {
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
    return try {
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
    }
}