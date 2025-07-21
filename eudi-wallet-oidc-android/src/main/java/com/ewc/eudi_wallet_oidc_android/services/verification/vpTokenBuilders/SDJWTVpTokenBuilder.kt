package com.ewc.eudi_wallet_oidc_android.services.verification.vpTokenBuilders

import android.util.Base64
import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.CredentialList
import com.ewc.eudi_wallet_oidc_android.models.InputDescriptors
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletAttestationUtil
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletAttestationUtil.generateHash
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationService
import com.nimbusds.jose.jwk.JWK
import org.json.JSONObject
import java.nio.charset.StandardCharsets

class SDJWTVpTokenBuilder : VpTokenBuilder {
    override fun build(
        credentialList: List<String>?,
        presentationRequest: PresentationRequest?,
        did: String?,
        jwk: JWK?,
        inputDescriptors: Any?
    ): String? {
                val claims = mutableMapOf<String, Any>()
                Log.d(
                    "ProcessTokenRequest:",
                    "transaction data = ${presentationRequest?.transactionDdata}"
                )
                if (presentationRequest?.transactionDdata?.isNotEmpty() == true) {
                    val transactionDataItem =
                        presentationRequest.transactionDdata?.getOrNull(0)
                    if (checkTransactionDataWithInputDescriptor(inputDescriptors, transactionDataItem)) {
                        val hash = generateHash(transactionDataItem ?: "")
                        Log.d(
                            "ProcessTokenRequest:",
                            "transactionDataItem has added:${hash}"
                        )
                        if (transactionDataItem != null) {
                            claims["transaction_data_hashes"] = listOf(hash)
                            claims["transaction_data_hashes_alg"] = "sha-256"
                        }
                    }
                } else {
                    Log.d(
                        "ProcessTokenRequest:",
                        "transaction data not added to claims"
                    )
                }
                val tempCredenital = "${credentialList?.getOrNull(0)}${if (credentialList?.getOrNull(0)?.endsWith("~") == true) "" else "~"}"
                val keyBindingResponse = WalletAttestationUtil.createKeyBindingJWT(
                    aud = presentationRequest?.clientId,
                    credential = tempCredenital,
                    subJwk = jwk,
                    claims = if (claims.isNotEmpty()) claims else null,
                    nonce = presentationRequest?.nonce

                )
                if (keyBindingResponse != null) {
                    val updatedCredential =
                        "$tempCredenital$keyBindingResponse"

                   return updatedCredential
                }else{
                  return credentialList?.getOrNull(0)
                }


    }
    private fun checkTransactionDataWithInputDescriptor(
        inputDescriptors: Any?,
        transactionDataItem: String?
    ): Boolean {
        return try {
            val decodedData = String(Base64.decode(transactionDataItem, Base64.URL_SAFE), StandardCharsets.UTF_8)
            val jsonObject = JSONObject(decodedData)
            val credentialIds = jsonObject.optJSONArray("credential_ids")?.let { array ->
                List(array.length()) { array.getString(it) }
            } ?: emptyList()
            when (inputDescriptors) {
                is InputDescriptors -> {
                   inputDescriptors?.id in credentialIds
                }
                is CredentialList ->{
                  inputDescriptors?.id in credentialIds
                }
                else -> false
            }
        } catch (e: Exception) {
            Log.e("VerificationService", "Error processing transaction data: ${e.message}")
            false
        }
    }
}