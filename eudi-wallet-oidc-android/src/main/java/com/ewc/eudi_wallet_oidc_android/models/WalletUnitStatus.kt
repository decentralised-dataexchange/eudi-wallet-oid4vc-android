package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.JsonObject
import com.google.gson.JsonParser

/**
 * The state of a wallet unit at the wallet provider
 * (`POST {base}/wallet-unit/status`).
 */
data class WalletUnitStatus(
    /** `active`, `suspended` or `revoked`. */
    val status: String,
    /** `user_request`, `device_policy`, `wallet_provider`, `key_compromise`, `app_removed`, or null. */
    val reason: String? = null,
    /** RFC 3339, when revoked. */
    val revokedAt: String? = null,
    /** The next status read must carry device evidence. */
    val deviceCheckDue: Boolean = false,
    /**
     * False for a unit that registered before it had a revocation code: ask
     * `wallet-unit/revocation-code` once.
     */
    val revocationCodeIssued: Boolean = true
) {
    val isActive: Boolean get() = status == ACTIVE
    val isSuspended: Boolean get() = status == SUSPENDED

    /** A revocation is final: send no more WIA requests for this unit. */
    val isRevoked: Boolean get() = status == REVOKED

    companion object {
        const val ACTIVE = "active"
        const val SUSPENDED = "suspended"
        const val REVOKED = "revoked"

        /**
         * Reads a status answer. Null when it has no `status`. A missing
         * `revocationCodeIssued` reads as issued, so the app does not ask for
         * a code a wallet provider cannot give.
         */
        fun parse(json: String?): WalletUnitStatus? = try {
            val root = JsonParser.parseString(json ?: "").asJsonObject
            val status = root.text("status")
            if (status.isNullOrEmpty()) null else WalletUnitStatus(
                status = status,
                reason = root.text("reason"),
                revokedAt = root.text("revokedAt"),
                deviceCheckDue = root.flag("deviceCheckDue") ?: false,
                revocationCodeIssued = root.flag("revocationCodeIssued") ?: true
            )
        } catch (e: Exception) {
            null
        }

        private fun JsonObject.text(name: String): String? =
            get(name)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString

        private fun JsonObject.flag(name: String): Boolean? =
            get(name)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean
    }
}

/** The result of a protocol 2 request that gives a value. */
sealed class WalletProviderOutcome<out T> {
    data class Success<T>(val value: T) : WalletProviderOutcome<T>()

    /**
     * `error.errorId` and `error.reason` name a refusal of the wallet provider;
     * `error.error` is one of [ErrorCodes] when the SDK could not make the
     * request or reach the wallet provider.
     */
    data class Failed(val error: ErrorResponse) : WalletProviderOutcome<Nothing>()
}

/** The result of a status read. */
sealed class WalletUnitStatusOutcome {
    data class Known(val status: WalletUnitStatus) : WalletUnitStatusOutcome()

    /**
     * The wallet provider does not know this unit (404 `unit_not_found`), or
     * the unit was never registered: the next WIA request registers it.
     */
    object NotRegistered : WalletUnitStatusOutcome()

    /** The wallet provider has no protocol 2 (404 without `error_id`). Show nothing. */
    object NotSupported : WalletUnitStatusOutcome()

    data class Failed(val error: ErrorResponse) : WalletUnitStatusOutcome()
}

/** The result of a revocation code request. */
sealed class WalletUnitRevocationCodeOutcome {
    /** Show the code once; never store it in plain text and never log it. */
    data class Issued(val code: String) : WalletUnitRevocationCodeOutcome() {
        override fun toString(): String = "Issued(code=<hidden>)"
    }

    /** 409 `revocation_code_exists`: another request already got the code. */
    object AlreadyIssued : WalletUnitRevocationCodeOutcome()

    /** The wallet provider has no protocol 2, or the unit is not registered. */
    object NotSupported : WalletUnitRevocationCodeOutcome()

    data class Failed(val error: ErrorResponse) : WalletUnitRevocationCodeOutcome()
}
