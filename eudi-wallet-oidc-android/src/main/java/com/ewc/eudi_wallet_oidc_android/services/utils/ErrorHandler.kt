package com.ewc.eudi_wallet_oidc_android.services.utils

import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import org.json.JSONArray
import org.json.JSONObject

object ErrorHandler {
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
                val errorList = JSONArray(jsonObject.getString("errors"))
                ErrorResponse(
                    error = -1,
                    errorDescription = errorList.getJSONObject(0).getString("message")
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

            else -> {
                ErrorResponse(
                    error = -1,
                    errorDescription = err
                )
            }
        }
        return errorResponse

    }
}