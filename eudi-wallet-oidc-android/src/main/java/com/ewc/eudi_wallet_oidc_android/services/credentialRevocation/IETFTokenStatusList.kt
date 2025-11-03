package com.ewc.eudi_wallet_oidc_android.services.credentialRevocation

import android.util.Log
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall.safeApiCallCallback
import com.ewc.eudi_wallet_oidc_android.services.utils.CborUtils
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils
import com.google.gson.Gson
import com.google.gson.JsonObject
import okhttp3.ResponseBody
import org.json.JSONObject
import retrofit2.Call
import retrofit2.Callback
import retrofit2.Response
import java.math.BigInteger
import java.util.Base64

class IETFTokenStatusList: StatusListInterface {
    data class StatusModel(
        val statusUri: String,
        val ietfTokenStatusListModel: IETFTokenStatusListModel
    )
    override fun extractUniqueStatusUris(credentials: List<String?>): List<String> {
        val statusUris = mutableSetOf<String>()

        // Loop through each credential and extract the unique URI
        for (credential in credentials) {
            if (credential.isNullOrBlank()) continue

            val (idx, uri) = extractStatusDetails(credential) ?: continue
            if (uri != null) {
                statusUris.add(uri)
            }
        }

        return statusUris.toList()
    }
    override fun extractStatusDetails(credential: String): Pair<Int?, String?>? {
        return try {
            if (JwtUtils.isValidJWT(credential)) {
                val jwtParts = credential.split(".")
                val payloadBase64 = jwtParts[1]
                val decodedPayload = try {
                    String(Base64.getDecoder().decode(payloadBase64))
                } catch (e: IllegalArgumentException) {
                    Log.e("Base64 Decoding Error", e.message.toString())
                    return null
                }

                val jsonPayload = try {
                    Gson().fromJson(decodedPayload, JsonObject::class.java)
                } catch (e: Exception) {
                    Log.e("Error parsing JWT payload", e.message.toString())
                    return null
                }

                val status = jsonPayload.getAsJsonObject("status") ?: run {
                    Log.e("Error", "'status' field not found in JWT payload.")
                    return null
                }

                val statusList = status.getAsJsonObject("status_list") ?: run {
                    Log.e("Error", "'status_list' field not found in 'status' object.")
                    return null
                }

                val idx = statusList.get("idx")?.asInt
                val uri = statusList.get("uri")?.asString

                if (idx == null || uri == null) {
                    Log.e("Error", "Missing 'idx' or 'uri' in 'status_list'.")
                    return null
                }

                return Pair(idx, uri)
            } else  {
                return try {
                    val issuerAuth = CborUtils.processExtractIssuerAuth(listOf(credential))
                    val statusList = CborUtils.getStatusList(issuerAuth)

                    val idx = (statusList?.get("idx") as? BigInteger)?.toInt()
                    val uri = statusList?.get("uri") as? String

                    if (idx == null || uri == null) {
                        Log.e("Error", "Missing 'idx' or 'uri' in 'status_list'.")
                        return null
                    }
                    Pair(idx, uri)
                } catch (e: Exception) {
                    Log.e("CBOR Processing Error", e.message.toString())
                    null
                }
            }
        } catch (e: Exception) {
            Log.e("extractStatusDetails", "Unexpected error: ${e.message}")
            null
        }
    }
    fun fetchStatusFromServer(uris: List<String>, callback: (List<StatusModel>) -> Unit) {
        val statusModels = mutableListOf<StatusModel>()
        val apiService = ApiManager.api.getService()
        var remainingRequests = uris.size

        for (uri in uris) {
            val call = apiService?.getStatusList(uri, "application/statuslist+jwt")

            safeApiCallCallback(
                call,
                onSuccess = { responseBody ->
                    try {
                        val responseString = responseBody.string()
                        Log.d("StatusList", "Success: $responseString")

                        val result = decodeStatusListJwt(responseString)
                        if (result != null) {
                            val (fetchDecodedString, bits) = result
                            if (fetchDecodedString != null && bits != null) {
                                val iETFTokenStatusListModel =
                                    IETFTokenStatusListModel.fromEncoded(fetchDecodedString, bits)
                                val statusModel = StatusModel(uri, iETFTokenStatusListModel)
                                statusModels.add(statusModel)
                            }
                        }
                    } catch (e: Exception) {
                        Log.e("StatusList", "Parsing error: ${e.message}")
                    } finally {
                        remainingRequests--
                        if (remainingRequests == 0) {
                            callback(statusModels)
                        }
                    }
                },
                onError = { errorMsg ->
                    Log.e("StatusList", "Error for $uri: $errorMsg")
                    remainingRequests--
                    if (remainingRequests == 0) {
                        callback(statusModels)
                    }
                }
            )
        }
    }
    fun decodeStatusListJwt(statusListJwt: String): Pair<String?, Int?>? {

        val parts = statusListJwt.split(".")
        if (parts.size != 3) {
            Log.e("JWT", "Invalid JWT format")
            return null
        }

        val payload = parts[1]

        val decodedPayload = String(Base64.getUrlDecoder().decode(payload))

        val jsonObject = JSONObject(decodedPayload)

        val statusList = jsonObject.optJSONObject("status_list")

        val statusListString =
            if (statusList?.has("lst") == true) statusList.optString("lst") else null

        val bitsValue = if (statusList?.has("bits") == true) statusList.optInt("bits") else null

        if (statusListString == null) {
            Log.e("decodeStatusListJwt", "'lst' key not found in the status_list object")
            return null
        }

        return Pair(statusListString, bitsValue)
    }


}