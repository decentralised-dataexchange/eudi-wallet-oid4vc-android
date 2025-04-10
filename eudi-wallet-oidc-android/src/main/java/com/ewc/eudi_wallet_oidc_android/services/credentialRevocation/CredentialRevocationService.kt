package com.ewc.eudi_wallet_oidc_android.services.credentialRevocation

import android.util.Log
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils
import com.google.gson.Gson
import com.google.gson.JsonObject
import java.util.Base64

class CredentialRevocationService : CredentialRevocationServiceInterface{


    override fun getRevokedCredentials(credentials: List<String?>, callback: (List<String>) -> Unit) {
        if (credentials.isNullOrEmpty()) {
            callback(emptyList())
            return
        }
        // Create a list to store revoked credentials
        val revokedStatusList = mutableListOf<String>()
        val statusList2021 = mutableListOf<String>()
        val ietfStatusList = mutableListOf<String>()
        for (credential in credentials) {
            if (credential.isNullOrBlank()) continue

            try {
                //if (!JwtUtils.isValidJWT(credential)) continue
                if (JwtUtils.isValidJWT(credential)) {
                    val jwtParts = credential.split(".")
                    if (jwtParts.size < 2) continue

                    val payloadBase64 = jwtParts[1]
                    val decodedPayload = String(Base64.getUrlDecoder().decode(payloadBase64))
                    val jsonPayload = Gson().fromJson(decodedPayload, JsonObject::class.java)

                    // ✅ Safe check for StatusList2021Entry
                    val vc = jsonPayload.getAsJsonObject("vc")
                    val credentialStatus = vc?.getAsJsonObject("credentialStatus")
                    val type = credentialStatus?.get("type")?.asString

                    if (type == "StatusList2021Entry") {
                        statusList2021.add(credential)
                    }

                    // ✅ Safe check for status.status_list
                    val status = jsonPayload.getAsJsonObject("status")
                    val statusList = status?.getAsJsonObject("status_list")
                    if (statusList != null) {
                        ietfStatusList.add(credential)
                    }
                }
                else{
                    ietfStatusList.add(credential)
                }


            } catch (e: Exception) {
                Log.e("getRevokedCredentials", "Failed to process credential: ${e.message}")
                continue
            }
        }
        val ietfUris = if (ietfStatusList.isNotEmpty()) {
            IETFTokenStatusList().extractUniqueStatusUris(ietfStatusList)
        } else emptyList()

        val statusList2021Uris = if (statusList2021.isNotEmpty()) {
            VerifiableCredentialStatusList2021().extractUniqueStatusUris(statusList2021)
        } else emptyList()

        // ✅ Unified check if both lists are empty
        if (ietfUris.isEmpty() && statusList2021Uris.isEmpty()) {
            callback(emptyList())
            return
        }
        var remainingTasks = 0

        if (ietfStatusList.isNotEmpty()) remainingTasks++
        if (statusList2021.isNotEmpty()) remainingTasks++

        fun taskFinished() {
            remainingTasks--
            if (remainingTasks == 0) {
                callback(revokedStatusList)
            }
        }
        if (ietfStatusList.isNotEmpty()){
            println(ietfUris)
            IETFTokenStatusList().fetchStatusFromServer(ietfUris) { statusModels ->

                for (credential in credentials) {
                    if (credential.isNullOrBlank()) continue // Skip null or blank credentials
                    val (idx, uri) = IETFTokenStatusList().extractStatusDetails(credential) ?: continue
                    for (statusModel in statusModels) {
                        if (statusModel.statusUri == uri) {
                            val correspondingStatusList = statusModel.ietfTokenStatusListModel
                            val valueAtPosition = idx?.let { correspondingStatusList.get(it) }
                            if (valueAtPosition == 1) {
                                revokedStatusList.add(credential)
                            }
                        }
                    }
                }
                taskFinished()
            }
        }

        if (statusList2021.isNotEmpty()){

            println(statusList2021Uris)
            VerifiableCredentialStatusList2021().fetchStatusFromServer(statusList2021Uris) { statusModels ->
                for (credential in credentials) {
                    if (credential.isNullOrBlank()) continue // Skip null or blank credentials
                    val (idx, uri) = VerifiableCredentialStatusList2021().extractStatusDetails(credential) ?: continue
                    for (statusModel in statusModels) {
                        if (statusModel.statusUri == uri) {
                            val correspondingStatusList = statusModel.verifiableCredentialsStatusList2021Model
                            val valueAtPosition = idx?.let { correspondingStatusList.getBit(it) }
                            if (valueAtPosition == '1')  {
                                revokedStatusList.add(credential)
                            }
                        }
                    }
                }
                taskFinished()
            }
        }

    }
}
