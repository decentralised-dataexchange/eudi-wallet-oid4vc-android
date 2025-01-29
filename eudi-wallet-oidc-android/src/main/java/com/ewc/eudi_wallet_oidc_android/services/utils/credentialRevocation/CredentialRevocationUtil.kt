package com.ewc.eudi_wallet_oidc_android.services.utils.credentialRevocation

import android.util.Log
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.utils.CborUtils
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils
import com.google.gson.Gson
import com.google.gson.JsonObject
import okhttp3.ResponseBody
import org.json.JSONObject
import java.util.Base64
import retrofit2.Call
import retrofit2.Callback
import retrofit2.Response
import java.math.BigInteger
class CredentialRevocationUtil {
    data class StatusModel(
        val statusUri: String,
        val statusList: StatusList
    )

    fun credentialRevocation(credentials: List<String?>, callback: (List<String>) -> Unit) {
        if (credentials.isNullOrEmpty()) {
            callback(emptyList())
            return
        }
        // Create a list to store revoked credentials
        val revokedStatusList = mutableListOf<String>()
        var processedCount = 0
        val uniqueUris = extractUniqueStatusUris(credentials)
        if (uniqueUris.isEmpty()) {
            callback(emptyList())
            return
        }
        println(uniqueUris)

        fetchStatusFromServer(uniqueUris) { statusModels ->

            for (credential in credentials) {
                if (credential.isNullOrBlank()) continue // Skip null or blank credentials
                val (idx, uri) = extractStatusDetails(credential) ?: continue
                for (statusModel in statusModels) {
                    if (statusModel.statusUri == uri) {
                        val correspondingStatusList = statusModel.statusList
                        val valueAtPosition = idx?.let { correspondingStatusList.get(it) }
                        if (valueAtPosition == 1) {
                            revokedStatusList.add(credential)
                        }
                    }
                }
                processedCount++
            }

            if (processedCount == credentials.size) {

                callback(revokedStatusList)
            }
        }
    }

    private fun extractUniqueStatusUris(credentials: List<String?>): List<String> {
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

    private fun fetchStatusFromServer(uris: List<String>, callback: (List<StatusModel>) -> Unit) {
        val statusModels = mutableListOf<StatusModel>()
        val apiService = ApiManager.api.getService()

        var remainingRequests = uris.size

        for (uri in uris) {
            val call = uri?.let { apiService?.getStatusList(it, "application/statuslist+jwt") }

            call?.enqueue(object : Callback<ResponseBody> {
                override fun onResponse(
                    call: Call<ResponseBody>,
                    response: Response<ResponseBody>
                ) {
                    if (response.isSuccessful) {
                        // Handle the response
                        val responseBody = response.body()?.string()
                        Log.d("StatusList", "Success: $responseBody")
                        if (responseBody != null) {
                            // Decode the JWT and extract status list
                            val result = decodeStatusListJwt(responseBody)
                            if (result != null) {
                                val (fetchDecodedString, bits) = result
                                if (fetchDecodedString != null && bits != null) {
                                    val statusList =
                                        StatusList.fromEncoded(fetchDecodedString, bits)
                                    val statusModel = StatusModel(uri, statusList)
                                    statusModels.add(statusModel)
                                }
                            }
                        }
                    } else {
                        Log.e("StatusList", "Error: ${response.code()} - ${response.message()}")
                    }

                    remainingRequests--
                    if (remainingRequests == 0) {
                        callback(statusModels)
                    }
                }

                override fun onFailure(call: Call<ResponseBody>, t: Throwable) {
                    Log.e("StatusList", "Failure: ${t.message}")
                    remainingRequests--
                    if (remainingRequests == 0) {
                        callback(statusModels)
                    }
                }
            })
        }
    }

    private fun decodeStatusListJwt(statusListJwt: String): Pair<String?, Int?>? {

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

    private fun extractStatusDetails(credential: String): Pair<Int?, String?>? {
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

}
