package com.ewc.eudi_wallet_oidc_android.services.utils

import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.TrustedAuthority
import com.ewc.eudi_wallet_oidc_android.services.utils.trustEvaluator.TrustEvaluator


suspend fun filterByTrustedAuthorities(
    credentials: List<String>,
    trustedAuthorities: List<TrustedAuthority>
): List<String> {
    val finalFiltered = mutableListOf<String>()

    // Loop through each credential
    for (credential in credentials) {
        var isTrusted = false

        // Loop through each trusted authority definition
        for (authority in trustedAuthorities) {
            authority.values?.forEach { url ->
                try {
                    val trustedX5c = TrustEvaluator.findTrustedX5c(credential, null, listOf(url))
                    if (trustedX5c != null) {
                        isTrusted = true
                        return@forEach // found trust, no need to check further for this credential
                    }
                } catch (e: Exception) {
                    Log.e("TrustListUtils", "Trust check failed: ${e.message}")
                }
            }
            if (isTrusted) break
        }

        if (isTrusted) {
            finalFiltered.add(credential)
        }
    }

    return finalFiltered
}

