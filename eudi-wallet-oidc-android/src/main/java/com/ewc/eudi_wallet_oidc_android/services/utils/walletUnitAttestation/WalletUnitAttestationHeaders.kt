package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation

import android.util.Base64
import com.google.gson.Gson
import com.google.gson.JsonObject

/**
 * Single home for attaching a Wallet Unit Attestation (WUA) to outgoing requests:
 * the OAuth-Client-Attestation / OAuth-Client-Attestation-PoP header pair and the
 * client_id rule (sub claim of the WUA JWT, fallback to the DID).
 */
object WalletUnitAttestationHeaders {
    const val CLIENT_ATTESTATION = "OAuth-Client-Attestation"
    const val CLIENT_ATTESTATION_POP = "OAuth-Client-Attestation-PoP"

    /** Builds the WUA header pair. Strips one trailing "~" from the JWT. Skips null/empty values. */
    fun build(
        walletUnitAttestationJWT: String?,
        walletUnitProofOfPossession: String?
    ): MutableMap<String, String> {
        return mutableMapOf<String, String>().apply {
            if (!walletUnitAttestationJWT.isNullOrEmpty()) {
                this[CLIENT_ATTESTATION] = walletUnitAttestationJWT.removeSuffix("~")
            }
            if (!walletUnitProofOfPossession.isNullOrEmpty()) {
                this[CLIENT_ATTESTATION_POP] = walletUnitProofOfPossession
            }
        }
    }

    /** client_id rule: sub claim of the WUA JWT, fallback to the DID. */
    fun clientId(walletUnitAttestationJWT: String?, fallbackDid: String?): String? {
        return extractSub(walletUnitAttestationJWT) ?: fallbackDid
    }

    private fun extractSub(jwt: String?): String? {
        try {
            if (jwt.isNullOrEmpty()) return null

            val parts = jwt.split(".")
            if (parts.size < 2) return null

            val payload = parts[1]
            // Base64 decode payload (URL-safe, no padding)
            val decodedBytes = Base64.decode(payload, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            val payloadJson = String(decodedBytes, Charsets.UTF_8)

            // Parse JSON
            val jsonObject = Gson().fromJson(payloadJson, JsonObject::class.java)
            return jsonObject.get("sub")?.asString
        } catch (e: Exception) {
            return null
        }
    }
}
