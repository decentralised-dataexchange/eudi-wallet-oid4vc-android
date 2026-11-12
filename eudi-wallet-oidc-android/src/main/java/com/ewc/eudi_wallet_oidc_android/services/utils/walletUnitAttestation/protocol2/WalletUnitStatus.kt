package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.protocol2

import com.google.gson.JsonObject
import com.google.gson.JsonParser

/**
 * The answer of `POST .../wallet-unit/status` (CONTRACT.md section 4):
 * `{"status", "reason", "revokedAt", "deviceCheckDue", "revocationCodeIssued"}`.
 */
data class WalletUnitStatus(
    /** `active`, `suspended` or `revoked`. */
    val status: String,
    /** `user_request`, `device_policy`, `wallet_provider`, `key_compromise`, `app_removed`, or null. */
    val reason: String? = null,
    /** RFC 3339, or null. */
    val revokedAt: String? = null,
    val deviceCheckDue: Boolean = false,
    val revocationCodeIssued: Boolean = true
) {
    val isActive: Boolean get() = status == ACTIVE
    val isSuspended: Boolean get() = status == SUSPENDED
    val isRevoked: Boolean get() = status == REVOKED

    companion object {
        const val ACTIVE = "active"
        const val SUSPENDED = "suspended"
        const val REVOKED = "revoked"

        /** Null when the body is not a status answer. */
        fun parse(body: String?): WalletUnitStatus? = try {
            val json = body?.let { JsonParser.parseString(it) }?.takeIf { it.isJsonObject }?.asJsonObject
            val status = json?.text("status")
            if (json == null || status == null) null else WalletUnitStatus(
                status = status,
                reason = json.text("reason"),
                revokedAt = json.text("revokedAt"),
                deviceCheckDue = json.flag("deviceCheckDue") ?: false,
                // A missing member is read as "issued": the app then asks for no code.
                revocationCodeIssued = json.flag("revocationCodeIssued") ?: true
            )
        } catch (e: Exception) {
            null
        }

        private fun JsonObject.text(name: String): String? =
            get(name)?.takeIf { it.isJsonPrimitive }?.asString

        private fun JsonObject.flag(name: String): Boolean? =
            get(name)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean
    }
}

/** The result of a status read. */
sealed class WalletUnitStatusResult {
    /** The wallet provider answered with the status of the unit. */
    data class Known(val status: WalletUnitStatus) : WalletUnitStatusResult()

    /**
     * No status: a wallet provider of protocol 1 (the route answers 404 with no `error_id`).
     * The app shows nothing.
     */
    object NotSupported : WalletUnitStatusResult()

    /**
     * The wallet provider does not know the request key (404 `unit_not_found`), or the app has
     * no registered request key: the next WIA request must register the device key.
     */
    object NotRegistered : WalletUnitStatusResult()

    /** An error answer or no answer. The app keeps what it has. */
    data class Failed(val error: WalletProviderError) : WalletUnitStatusResult()

    companion object {
        /** The result for an HTTP answer of the status route. */
        fun fromAnswer(httpCode: Int, body: String?): WalletUnitStatusResult {
            if (httpCode in 200..299) {
                return WalletUnitStatus.parse(body)?.let { Known(it) }
                    ?: Failed(WalletProviderError(httpCode))
            }
            val error = WalletProviderError.parse(httpCode, body)
            return when {
                error.errorId == WalletProviderError.UNIT_NOT_FOUND -> NotRegistered
                httpCode == 404 && error.errorId == null -> NotSupported
                // The status route gives revoked and suspended as a 200 answer; a 403 of the
                // general check of section 3.8 says the same.
                error.action == WalletProviderErrorAction.REVOKED ->
                    Known(WalletUnitStatus(WalletUnitStatus.REVOKED, reason = error.reason))
                error.action == WalletProviderErrorAction.SUSPENDED ->
                    Known(WalletUnitStatus(WalletUnitStatus.SUSPENDED, reason = error.reason))
                else -> Failed(error)
            }
        }
    }
}
