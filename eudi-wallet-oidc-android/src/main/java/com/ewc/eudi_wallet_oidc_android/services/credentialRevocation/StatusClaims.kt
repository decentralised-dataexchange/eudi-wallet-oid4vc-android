package com.ewc.eudi_wallet_oidc_android.services.credentialRevocation

import com.google.gson.JsonObject

/**
 * Single home for locating the status claim of a credential JWT payload:
 * the classic top-level "status", or "client_status.status" on an
 * ARF TS3 v1.5 Wallet Instance Attestation.
 */
object StatusClaims {
    fun of(payload: JsonObject): JsonObject? {
        return payload.getAsJsonObject("status")
            ?: payload.getAsJsonObject("client_status")?.getAsJsonObject("status")
    }
}
