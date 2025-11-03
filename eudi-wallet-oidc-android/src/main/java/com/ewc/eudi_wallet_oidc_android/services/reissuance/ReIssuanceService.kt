package com.ewc.eudi_wallet_oidc_android.services.reissuance

import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.AuthorizationDetail
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.CredentialRequest
import com.ewc.eudi_wallet_oidc_android.models.CredentialRequestEncryptionInfo
import com.ewc.eudi_wallet_oidc_android.models.ECKeyWithAlgEnc
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.ProofV3
import com.ewc.eudi_wallet_oidc_android.models.ProofsV3
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedCredentialResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.IssueService
import com.ewc.eudi_wallet_oidc_android.services.issue.credentialResponseEncryption.CredentialEncryptionBuilder
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall
import com.ewc.eudi_wallet_oidc_android.services.utils.ErrorHandler
import com.ewc.eudi_wallet_oidc_android.services.utils.ProofService
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse.JWEEncrypter
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.nimbusds.jose.jwk.JWK
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody

class ReIssuanceService : ReIssuanceServiceInterface {
    override suspend fun reIssueCredential(
        did: String?,
        subJwk: JWK?,
        nonce: String?,
        credentialOffer: CredentialOffer?,
        issuerConfig: IssuerWellKnownConfiguration?,
        accessToken: TokenResponse?,
        authorizationDetail: AuthorizationDetail?,
        index: Int,
        ecKeyWithAlgEnc: ECKeyWithAlgEnc?,
        credentialRequestEncryptionInfo: CredentialRequestEncryptionInfo?,
        interactiveAuthorizationEndpoint: String?
    ): WrappedCredentialResponse? {


        val credentialEncryptionBuilder = CredentialEncryptionBuilder()
        val jwt = ProofService().createProof(did, subJwk, nonce, issuerConfig, credentialOffer)
        if (jwt == null) {
            Log.e("IssueService", "Failed to create proof for credential request")
            return null
        }

        val request: CredentialRequest =
            if (authorizationDetail != null && authorizationDetail.type == "openid_credential" && !authorizationDetail.credentialIdentifiers.isNullOrEmpty()) {

                CredentialRequest(
                    credentialIdentifier = authorizationDetail.credentialIdentifiers.firstOrNull(),
                    proof = ProofV3(jwt = jwt, proofType = "jwt"),
                )
            } else if (authorizationDetail != null && authorizationDetail.type == "openid_credential" &&
                issuerConfig?.nonceEndpoint != null && !authorizationDetail.credentialConfigurationId.isNullOrBlank()
            ) {
                CredentialRequest(
                    credentialConfigurationId = authorizationDetail.credentialConfigurationId,
                    proof = ProofV3(jwt = jwt, proofType = "jwt"),
                )
            } else if (accessToken?.cNonce == null && issuerConfig?.nonceEndpoint != null && accessToken?.authorizationDetails.isNullOrEmpty()) {

                CredentialRequest(
                    credentialConfigurationId = credentialOffer?.credentials?.get(index)?.types?.firstOrNull(),
                    proof = ProofV3(jwt = jwt, proofType = "jwt"),
                )
            } else {

                val doctype = IssueService().fetchDoctype(index, credentialOffer, issuerConfig)
                var types: ArrayList<String> = ArrayList()
                var format: String? = null
                try {
                    types = credentialOffer?.credentials?.get(index)?.types
                        ?: credentialOffer?.credentials?.get(index)?.doctype?.let { arrayListOf(it) }
                                ?: ArrayList()
                    format = IssueService().getFormatFromIssuerConfig(
                        issuerConfig,
                        types.lastOrNull() ?: ""
                    )
                } catch (e: Exception) {
                }
                IssueService().buildCredentialRequest(
                    credentialOffer = credentialOffer,
                    issuerConfig = issuerConfig,
                    format = format,
                    doctype = doctype,
                    jwt = jwt, index = index
                )
            }
        if (credentialRequestEncryptionInfo?.encryptionRequired != null || interactiveAuthorizationEndpoint != null) {
            request.proofs = ProofsV3(jwt = arrayListOf(jwt))
            request.proof = null
        }

        request.credentialResponseEncryption = credentialEncryptionBuilder.build(ecKeyWithAlgEnc)

        return try {
            val result = SafeApiCall.safeApiCallResponse {
                if (credentialRequestEncryptionInfo?.encryptionRequired == true) {
                    if (credentialRequestEncryptionInfo.jwk != null) {
                        val type = object : TypeToken<Map<String, Any?>>() {}.type
                        val payload: Map<String, Any?> = Gson().fromJson(Gson().toJson(request), type)

                        val encryptedJwe = JWEEncrypter().encrypt(
                            payload = payload,
                            jwk = credentialRequestEncryptionInfo.jwk
                        )
                        val requestBody = encryptedJwe
                            .toRequestBody("application/jwt".toMediaType())

                        ApiManager.api.getService()?.getCredentialEncrypted(
                            issuerConfig?.credentialEndpoint ?: "",
                            "application/jwt",
                            "Bearer ${accessToken?.accessToken}",
                            requestBody
                        )
                    } else null
                } else {
                    ApiManager.api.getService()?.getCredential(
                        issuerConfig?.credentialEndpoint ?: "",
                        "application/json",
                        "Bearer ${accessToken?.accessToken}",
                        request
                    )
                }
            }

            result.fold(
                onSuccess = { response ->
                    IssueService().parseCredentialResponse(
                        response,
                        ecKeyWithAlgEnc,
                        credentialEncryptionBuilder
                    )
                },
                onFailure = { error ->
                    Log.e("IssueService", "Error reissuing credential: ${error.message}")
                    WrappedCredentialResponse(
                        credentialResponse = null,
                        errorResponse = ErrorResponse(errorDescription = error.message)
                    )
                }
            )
        } catch (e: Exception) {
            Log.e("IssueService", "Unexpected error while reissuing credential: ${e.message}")
            null
        }
    }
}