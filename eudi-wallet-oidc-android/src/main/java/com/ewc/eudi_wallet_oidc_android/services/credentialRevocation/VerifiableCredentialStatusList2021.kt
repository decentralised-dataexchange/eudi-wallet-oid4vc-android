package com.ewc.eudi_wallet_oidc_android.services.credentialRevocation

import android.util.Log
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils
import com.google.gson.Gson
import com.google.gson.JsonObject
import okhttp3.ResponseBody
import org.json.JSONObject
import retrofit2.Call
import retrofit2.Callback
import retrofit2.Response
import java.util.Base64

class VerifiableCredentialStatusList2021:StatusListInterface {
    data class StatusModel(
        val statusUri: String,
        val verifiableCredentialsStatusList2021Model: VerifiableCredentialsStatusList2021Model
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

                val vc = jsonPayload.getAsJsonObject("vc") ?: run {
                    Log.e("Error", "'vc' field not found in JWT payload.")
                    return null
                }
                val credentialStatus = vc.getAsJsonObject("credentialStatus")?: run {
                    Log.e("Error", "'credentialStatus' field not found in JWT payload.")
                    return null
                }
                val statusListIndexElement = credentialStatus.get("statusListIndex")
                val idx = when {
                    statusListIndexElement?.isJsonPrimitive == true -> {
                        val primitive = statusListIndexElement.asJsonPrimitive
                        when {
                            primitive.isNumber -> primitive.asInt
                            primitive.isString -> primitive.asString.toIntOrNull()
                            else -> null
                        }
                    }
                    else -> null
                }
                val uri = credentialStatus.get("statusListCredential")?.asString


                if (idx == null || uri == null) {
                    Log.e("Error", "Missing 'idx' or 'uri' in 'status_list'.")
                    return null
                }

                return Pair(idx, uri)
            }else{
                null
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
            val call = uri?.let { apiService?.getVerifiableCredentialStatusList(it) }

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
                                val verifiableCredentialsStatusList2021Model =
                                    VerifiableCredentialsStatusList2021Model(result)
                                val statusModel = StatusModel(
                                    uri,
                                    verifiableCredentialsStatusList2021Model
                                )
                                statusModels.add(statusModel)
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

     fun decodeStatusListJwt(statusListJwt: String): String? {
        return try {
            val parts = statusListJwt.split(".")
            if (parts.size != 3) {
                Log.e("JWT", "Invalid JWT format")
                return null
            }

            val payload = parts[1]
            val decodedPayload = String(Base64.getUrlDecoder().decode(payload))
            val jsonObject = JSONObject(decodedPayload)

            val vc = jsonObject.optJSONObject("vc")
            val credentialSubject = vc?.optJSONObject("credentialSubject")

            val encodedListString = credentialSubject?.optString("encodedList", null)

            if (encodedListString == null) {
                Log.e("decodeStatusListJwt", "'encodedList' key not found in credentialStatus")
                null
            } else {
                encodedListString
            }
        } catch (e: Exception) {
            Log.e("decodeStatusListJwt", "Error decoding JWT: ${e.localizedMessage}")
            null
        }
    }


}