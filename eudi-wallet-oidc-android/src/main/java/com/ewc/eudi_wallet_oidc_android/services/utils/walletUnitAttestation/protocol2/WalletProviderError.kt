package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.protocol2

import com.google.gson.JsonObject
import com.google.gson.JsonParser

/**
 * What the app does for an error answer of the wallet provider (CONTRACT.md section 4).
 */
enum class WalletProviderErrorAction {
    /** `app_version_too_old`, `app_unknown`: the "Update the app" screen and an immediate store update. */
    UPDATE_APP,

    /** `revoked`: the "Wallet unit revoked" screen with the reason; the WIA card shows Revoked. */
    REVOKED,

    /** `suspended`: the WIA card shows Suspended. */
    SUSPENDED,

    /** `device_refused`: the "Device not accepted" screen with the reason. */
    DEVICE_REFUSED,

    /** `request_signature_invalid`: send the request again once with a new nonce, then a general error. */
    RETRY_WITH_NEW_NONCE,

    /** `protocol_1_refused`: only a protocol 1 app gets it; nothing to show. */
    NOTHING,

    /** Any other answer: a general error; the app keeps the stored WIA. */
    GENERAL
}

/**
 * An error answer of a wallet provider route: `{"error", "error_description", "error_id"}` and
 * `reason` where the contract names one. [httpCode] is null for a transport failure (no answer).
 */
data class WalletProviderError(
    val httpCode: Int?,
    val errorId: String? = null,
    val error: String? = null,
    val errorDescription: String? = null,
    val reason: String? = null
) {
    val action: WalletProviderErrorAction
        get() = actionFor(errorId)

    /** True when no wallet provider answered (network failure). */
    val isTransport: Boolean
        get() = httpCode == null

    companion object {
        const val APP_VERSION_TOO_OLD = "individual_wallet_unit.app_version_too_old"
        const val APP_UNKNOWN = "individual_wallet_unit.app_unknown"
        const val REVOKED = "individual_wallet_unit.revoked"
        const val SUSPENDED = "individual_wallet_unit.suspended"
        const val DEVICE_REFUSED = "individual_wallet_unit.device_refused"
        const val REQUEST_SIGNATURE_INVALID = "individual_wallet_unit.request_signature_invalid"
        const val PROTOCOL_1_REFUSED = "individual_wallet_unit.protocol_1_refused"
        const val UNIT_NOT_FOUND = "individual_wallet_unit.unit_not_found"
        const val REVOCATION_CODE_EXISTS = "individual_wallet_unit.revocation_code_exists"

        fun actionFor(errorId: String?): WalletProviderErrorAction = when (errorId) {
            APP_VERSION_TOO_OLD, APP_UNKNOWN -> WalletProviderErrorAction.UPDATE_APP
            REVOKED -> WalletProviderErrorAction.REVOKED
            SUSPENDED -> WalletProviderErrorAction.SUSPENDED
            DEVICE_REFUSED -> WalletProviderErrorAction.DEVICE_REFUSED
            REQUEST_SIGNATURE_INVALID -> WalletProviderErrorAction.RETRY_WITH_NEW_NONCE
            PROTOCOL_1_REFUSED -> WalletProviderErrorAction.NOTHING
            else -> WalletProviderErrorAction.GENERAL
        }

        /** Reads an error body. A body that is not a JSON object gives an error with no id. */
        fun parse(httpCode: Int?, body: String?): WalletProviderError {
            val json = try {
                body?.let { JsonParser.parseString(it) }?.takeIf { it.isJsonObject }?.asJsonObject
            } catch (e: Exception) {
                null
            } ?: return WalletProviderError(httpCode)
            return WalletProviderError(
                httpCode = httpCode,
                errorId = json.text("error_id"),
                error = json.text("error"),
                errorDescription = json.text("error_description"),
                reason = json.text("reason")
            )
        }

        private fun JsonObject.text(name: String): String? =
            get(name)?.takeIf { it.isJsonPrimitive }?.asString
    }
}
