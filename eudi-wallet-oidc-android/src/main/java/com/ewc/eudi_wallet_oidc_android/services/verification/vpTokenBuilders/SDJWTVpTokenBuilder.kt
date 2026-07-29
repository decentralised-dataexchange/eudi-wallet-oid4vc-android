package com.ewc.eudi_wallet_oidc_android.services.verification.vpTokenBuilders

import android.util.Base64
import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.CredentialList
import com.ewc.eudi_wallet_oidc_android.models.InputDescriptors
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.utils.createKeyBindingJWT
import com.ewc.eudi_wallet_oidc_android.services.utils.generateHash
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletAttestationUtil
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationService
import com.nimbusds.jose.jwk.JWK
import org.json.JSONObject
import java.nio.charset.StandardCharsets

class SDJWTVpTokenBuilder : VpTokenBuilder {
    override suspend fun build(
        credentialList: List<String>?,
        presentationRequest: PresentationRequest?,
        did: String?,
        jwk: JWK?,
        inputDescriptors: Any?,
        isScaFlow: Boolean
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
                val keyBindingResponse = createKeyBindingJWT(
                    aud = presentationRequest?.clientId,
                    credential = tempCredenital,
                    subJwk = jwk,
                    claims = if (claims.isNotEmpty()) claims else null,
                    nonce = presentationRequest?.nonce,
                    responseMode = if (isScaFlow) presentationRequest?.responseMode else null,
                    amr = if (isScaFlow) {
                        listOf(
                            mapOf("possession" to "key_in_local_native_wscd"),
                            mapOf("inherence" to "fingerprint_device")
                        )
                    } else null
                )
                if (keyBindingResponse != null) {
                    val updatedCredential =
                        "$tempCredenital$keyBindingResponse"

                   return updatedCredential
                }else{
                  return credentialList?.getOrNull(0)
                }


    }

    override suspend fun buildV2(
        credentialList: List<String>?,
        presentationRequest: PresentationRequest?,
        did: String?,
        jwk: JWK?,
        inputDescriptors: Any?,
        isScaFlow: Boolean,
        jwkList: List<JWK?>?
    ): List<String?> {
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
        // SCA (EWC/TS12): response_mode + amr belong in the KB-JWT ONLY for TS12 SCA transaction_data
        // types (payment / login_risk / account_access / emandate — URN or iGrant transaction-data-type
        // URL). They must NOT be added for EWC `payment_data` (PWA) or QES/QESAC flows. The DC API path
        // forwards isScaFlow=false, so we also detect SCA from the transaction_data type itself.
        val scaFlow = isScaFlow ||
            isTs12ScaTransactionData(presentationRequest?.transactionDdata?.getOrNull(0))
        val results = mutableListOf<String?>()
if (!credentialList.isNullOrEmpty()) {
    credentialList.forEachIndexed  { index, cred ->
        val credentialJwk = jwkList?.getOrNull(index) ?: jwk
        val tempCredential = "${cred}${if (cred.endsWith("~")) "" else "~"}"
        val keyBindingResponse = createKeyBindingJWT(
            aud = presentationRequest?.clientId,
            credential = tempCredential,
            subJwk = credentialJwk,
            claims = if (claims.isNotEmpty()) claims else null,
            nonce = presentationRequest?.nonce,
            responseMode = if (scaFlow) presentationRequest?.responseMode else null,
            amr = if (scaFlow) {
                listOf(
                    mapOf("possession" to "key_in_local_native_wscd"),
                    mapOf("inherence" to "fingerprint_device")
                )
            } else null
        )
        if (keyBindingResponse != null) {
            val updatedCredential = "$tempCredential$keyBindingResponse"
            results.add(updatedCredential)
        } else {
            results.add(cred)
        }
    }
}
return results

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

    // True only for TS12 SCA transaction_data types (payment / login_risk / account_access / emandate),
    // in either URN form (urn:eudi:sca:*) or the iGrant transaction-data-type URL form. Deliberately
    // returns false for EWC RFC-008 `payment_data` (PWA) and QES/QESAC — those are NOT SCA and must not
    // carry response_mode/amr in the KB-JWT.
    private fun isTs12ScaTransactionData(transactionDataItem: String?): Boolean {
        return try {
            if (transactionDataItem.isNullOrEmpty()) return false
            val decoded =
                String(Base64.decode(transactionDataItem, Base64.URL_SAFE), StandardCharsets.UTF_8)
            val type = JSONObject(decoded).optString("type", "")
            type.contains("urn:eudi:sca:") ||
                type.contains("transaction-data-type/payment") ||
                type.contains("transaction-data-type/login_risk") ||
                type.contains("transaction-data-type/account_access") ||
                type.contains("transaction-data-type/emandate")
        } catch (e: Exception) {
            false
        }
    }
}