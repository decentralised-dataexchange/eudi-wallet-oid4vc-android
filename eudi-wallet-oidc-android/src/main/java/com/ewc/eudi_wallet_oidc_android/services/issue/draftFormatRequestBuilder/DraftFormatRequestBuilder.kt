package com.ewc.eudi_wallet_oidc_android.services.issue.draftFormatRequestBuilder

import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.AuthorizationDetails
import com.ewc.eudi_wallet_oidc_android.models.CredentialDefinition
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.CredentialRequest
import com.ewc.eudi_wallet_oidc_android.models.CredentialRequestEncryptionInfo
import com.ewc.eudi_wallet_oidc_android.models.CredentialTypeDefinition
import com.ewc.eudi_wallet_oidc_android.models.ECKeyWithAlgEnc
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.ProofV3
import com.ewc.eudi_wallet_oidc_android.models.WrappedCredentialResponse
import com.ewc.eudi_wallet_oidc_android.models.v1.CredentialOfferEbsiV1
import com.ewc.eudi_wallet_oidc_android.models.v1.CredentialOfferEwcV1
import com.ewc.eudi_wallet_oidc_android.services.issue.IssueService
import com.ewc.eudi_wallet_oidc_android.services.issue.credentialResponseEncryption.CredentialEncryptionBuilder
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall
import com.google.gson.Gson
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.io.IOException

class DraftFormatRequestBuilder : DraftFormatRequestInterface {

    override fun buildAuthorizationRequest(
        credentialOffer: CredentialOffer?,
        format: String?,
        doctype: String?
    ): String {
        val gson = Gson()
        var credentialDefinitionNeeded = false
        try {
            if (credentialOffer?.credentials?.get(0)?.trustFramework == null)
                credentialDefinitionNeeded = true

        } catch (e: Exception) {
            credentialDefinitionNeeded = true
        }
        if (format == "mso_mdoc" && doctype != null) {
            return gson.toJson(
                arrayListOf(
                    AuthorizationDetails(
                        format = format,
                        doctype = doctype,
                        locations = arrayListOf(credentialOffer?.credentialIssuer ?: "")
                    )
                )
            )
        } else {
            if (credentialDefinitionNeeded) {
                return gson.toJson(
                    arrayListOf(
                        AuthorizationDetails(
                            format = format,
                            locations = arrayListOf(credentialOffer?.credentialIssuer ?: ""),
                            credentialDefinition = CredentialTypeDefinition(
                                type = IssueService().getTypesFromCredentialOffer(credentialOffer)
                            )
                        )
                    )
                )

            } else {
                return gson.toJson(
                    arrayListOf(
                        AuthorizationDetails(
                            format = format,
                            types = IssueService().getTypesFromCredentialOffer(credentialOffer),
                            locations = arrayListOf(credentialOffer?.credentialIssuer ?: "")
                        )
                    )
                )
            }
        }

    }

    override fun buildCredentialRequest(
        credentialOffer: CredentialOffer?,
        issuerConfig: IssuerWellKnownConfiguration?,
        format: String?,
        jwt: String,
        doctype: String?,
        index: Int
    ): CredentialRequest {

        val gson = Gson()
        var credentialDefinitionNeeded = false
        try {
            if (issuerConfig?.credentialsSupported is Map<*, *>)
                credentialDefinitionNeeded = true

        } catch (e: Exception) {
            credentialDefinitionNeeded = true
        }
        if (format == "mso_mdoc") {
            return CredentialRequest(
                format = format,
                doctype = doctype,
                proof = ProofV3(
                    proofType = "jwt",
                    jwt = jwt
                )
            )
        } else {
            if (credentialDefinitionNeeded) {
                var types: ArrayList<String>? =
                    IssueService().getTypesFromCredentialOffer(credentialOffer)
                when (val data = IssueService().getTypesFromIssuerConfig(
                    issuerConfig,
                    type = if (types?.isNotEmpty() == true) types.last() else "",
                    version = credentialOffer?.version,
                )) {
                    is ArrayList<*> -> {
                        return CredentialRequest(
                            credentialDefinition = CredentialDefinition(type = data as ArrayList<String>),
                            format = format,
                            proof = ProofV3(
                                proofType = "jwt",
                                jwt = jwt
                            )
                        )
                    }

                    is String -> {
                        return CredentialRequest(
                            vct = data as String,
                            format = format,
                            proof = ProofV3(
                                proofType = "jwt",
                                jwt = jwt
                            )
                        )
                    }
                }

                return CredentialRequest(
                    credentialDefinition = CredentialDefinition(type = types),
                    format = format,
                    proof = ProofV3(
                        proofType = "jwt",
                        jwt = jwt
                    )
                )
            } else {
                return CredentialRequest(
                    types = IssueService().getTypesFromCredentialOffer(credentialOffer),
                    format = format,
                    proof = ProofV3(
                        proofType = "jwt",
                        jwt = jwt
                    )
                )
            }
        }


    }

    override fun buildAuthorizationRequest(
        credentialOffer: CredentialOffer?,
        format: String?,
        doctype: String?,
        version: Int?,
        issuerConfig: IssuerWellKnownConfiguration?
    ): String {
        val gson = Gson()

        when (version) {
            1 -> {
                return buildAuthorizationRequest(
                    credentialOffer = credentialOffer,
                    format = format,
                    doctype = doctype
                )
            }

            else -> {
                val authorizationDetailList: ArrayList<AuthorizationDetails> = ArrayList()
                for (credential in credentialOffer?.credentials ?: arrayListOf()) {
                    authorizationDetailList.add(
                        AuthorizationDetails(
                            credentialConfigurationId = credential.types?.firstOrNull(),
                        )
                    )
                }
                return gson.toJson(authorizationDetailList)
            }
        }
    }

    override fun parseDraftCredentialOffer(credentialOfferJson: String?): CredentialOffer? {
        val gson = Gson()

        val credentialOfferEbsiV1Response = try {
            gson.fromJson(credentialOfferJson, CredentialOfferEbsiV1::class.java)
        } catch (e: Exception) {
            null
        }

        return if (credentialOfferEbsiV1Response?.credentials == null) {
            val credentialOfferEwcV1Response = try {
                gson.fromJson(credentialOfferJson, CredentialOfferEwcV1::class.java)
            } catch (e: Exception) {
                null
            }
            credentialOfferEwcV1Response?.let { CredentialOffer(ewcV1 = it) }
        } else {
            credentialOfferEbsiV1Response.let { CredentialOffer(ebsiV1 = it) }
        }
    }

    override fun getTxCodeParamKey(version: Int?): String? {
        return if (version == 1) "user_pin" else null
    }

    override suspend fun processDeferredCredentialRequest(
        acceptanceToken: String?,
        deferredCredentialEndPoint: String?,
        ecKeyWithAlgEnc: ECKeyWithAlgEnc?,
        credentialRequestEncryptionInfo: CredentialRequestEncryptionInfo?
    ): WrappedCredentialResponse? {
        val credentialEncryptionBuilder = CredentialEncryptionBuilder()
        return try {
            val result = SafeApiCall.safeApiCallResponse {
                ApiManager.api.getService()?.getDifferedCredential(
                    deferredCredentialEndPoint ?: "",
                    "Bearer $acceptanceToken",
                    CredentialRequest() // empty object
                )
            }

            result.fold(
                onSuccess = { response ->
                    IssueService().parseCredentialResponse(
                        response, ecKeyWithAlgEnc, credentialEncryptionBuilder
                    )
                },
                onFailure = { error ->
                    println("Error while fetching deferred credential: ${error.message}")
                    null
                }
            )
        } catch (e: IOException) {
            println("IOException while fetching deferred credential: ${e.message}")
            null
        } catch (e: Exception) {
            println("Unexpected error while fetching deferred credential: ${e.message}")
            null
        }
    }

    override fun getTypesFromIssuerConfig(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?
    ): Any? {
        var types: ArrayList<String> = ArrayList()
        // Check if issuerConfig is null
        if (issuerConfig == null) {
            return null
        }
        try {
            val credentialOfferJsonString = Gson().toJson(issuerConfig)
            // Check if credentialOfferJsonString is null or empty
            if (credentialOfferJsonString.isNullOrEmpty()) {
                return null
            }
            val jsonObject = JSONObject(credentialOfferJsonString)

            val credentialsSupported: Any = jsonObject.opt("credentials_supported") ?: return null
            when (credentialsSupported) {
                is JSONObject -> {
                    try {
                        val credentialSupported = credentialsSupported.getJSONObject(type ?: "")
                        val format =
                            if (credentialSupported.has("format")) credentialSupported.getString("format") else ""

                        if (format == "vc+sd-jwt" || format == "dc+sd-jwt") {
                            return credentialSupported.getJSONObject("credential_definition")
                                .getString("vct")
                        } else {
                            val typeFromCredentialIssuer: JSONArray =
                                credentialSupported.getJSONObject("credential_definition")
                                    .getJSONArray("type")
                            for (i in 0 until typeFromCredentialIssuer.length()) {
                                // Get each JSONObject from the JSONArray
                                val type: String = typeFromCredentialIssuer.getString(i)
                                types.add(type)
                            }
                            return types
                        }
                    } catch (e: Exception) {
                    }
                }

                is JSONArray -> {
                    try {
                        for (i in 0 until credentialsSupported.length()) {
                            val jsonObject: JSONObject = credentialsSupported.getJSONObject(i)

                            // Get the "types" JSONArray
                            val typesArray = jsonObject.getJSONArray("types")

                            // Check if the string is present in the "types" array
                            for (j in 0 until typesArray.length()) {
                                if (typesArray.getString(j) == type) {
                                    val format =
                                        if (jsonObject.has("format")) jsonObject.getString("format") else ""

                                    if (format == "vc+sd-jwt" || format == "dc+sd-jwt") {
                                        return jsonObject.getJSONObject("credential_definition")
                                            .getString("vct")
                                    } else {
                                        val typeFromCredentialIssuer: JSONArray =
                                            jsonObject.getJSONObject("credential_definition")
                                                .getJSONArray("type")
                                        for (i in 0 until typeFromCredentialIssuer.length()) {
                                            // Get each JSONObject from the JSONArray
                                            val type: String = typeFromCredentialIssuer.getString(i)
                                            types.add(type)
                                        }
                                        return types
                                    }
                                    break
                                }
                            }
                        }
                    } catch (e: Exception) {
                    }
                }

                else -> {
                    // Neither JSONObject nor JSONArray
                    println("Child is neither JSONObject nor JSONArray")
                }
            }
        } catch (e: JSONException) {
            Log.e("getTypesFromIssuerConfig", "Error parsing JSON", e)
        }

        return types
    }

}