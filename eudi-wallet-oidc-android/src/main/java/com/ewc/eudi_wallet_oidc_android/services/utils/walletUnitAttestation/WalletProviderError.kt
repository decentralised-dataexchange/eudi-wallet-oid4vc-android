package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation

import com.ewc.eudi_wallet_oidc_android.models.ErrorCodes
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse

/**
 * The `error_id` values of the wallet provider. Every one starts with
 * `individual_wallet_unit.`.
 */
object WalletProviderErrorId {
    const val APP_VERSION_TOO_OLD = "individual_wallet_unit.app_version_too_old"
    const val APP_UNKNOWN = "individual_wallet_unit.app_unknown"
    const val REVOKED = "individual_wallet_unit.revoked"
    const val SUSPENDED = "individual_wallet_unit.suspended"
    const val DEVICE_REFUSED = "individual_wallet_unit.device_refused"
    const val REGISTERED_ON_OTHER_DEVICE = "individual_wallet_unit.registered_on_other_device"
    const val UNIT_NOT_FOUND = "individual_wallet_unit.unit_not_found"
    const val REVOCATION_CODE_EXISTS = "individual_wallet_unit.revocation_code_exists"
    const val PROTOCOL_1_REFUSED = "individual_wallet_unit.protocol_1_refused"

    // Handled inside the SDK; the app does not see them unless a retry fails too.
    internal const val REQUEST_SIGNATURE_INVALID = "individual_wallet_unit.request_signature_invalid"
    internal const val DEVICE_REGISTERED_BEFORE = "individual_wallet_unit.device_registered_before"
    internal const val REQUEST_KEY_IN_USE = "individual_wallet_unit.request_key_in_use"
    internal const val DEVICE_KEY_ATTESTATION_MISSING = "individual_wallet_unit.device_key_attestation_missing"
}

/**
 * What went wrong on this side of a wallet provider request. Never thrown to
 * the app: [asErrorResponse] turns it into the outcome's error.
 */
internal sealed class WalletProviderError {
    object NonceUnavailable : WalletProviderError()

    /** The device key could not be made or used. */
    data class DeviceKey(val cause: Throwable) : WalletProviderError()

    /** Play Integrity gave no token. */
    data class Integrity(val cause: Throwable) : WalletProviderError()

    /** The device key of the registered unit is gone. */
    object KeyLost : WalletProviderError()

    object BodyNotSerialisable : WalletProviderError()
    object SigningFailed : WalletProviderError()
    data class Transport(val detail: String?) : WalletProviderError()

    /** A 2xx whose body is not what the route gives. */
    data class UnexpectedAnswer(val httpStatus: Int) : WalletProviderError()

    /** The wallet provider refused; the error carries `errorId` and `reason`. */
    data class Refused(val error: ErrorResponse) : WalletProviderError()

    fun asErrorResponse(): ErrorResponse = when (this) {
        is Refused -> error
        KeyLost -> failure(ErrorCodes.WALLET_UNIT_KEY_LOST, "The device key of the wallet unit is no longer on this device")
        is Transport -> failure(ErrorCodes.WALLET_PROVIDER_UNREACHABLE, detail ?: "The wallet provider could not be reached")
        is UnexpectedAnswer -> {
            val status = httpStatus
            failure(ErrorCodes.WALLET_PROVIDER_REQUEST_FAILED, "The wallet provider answer could not be read")
                .apply { httpStatus = status }
        }
        NonceUnavailable -> failure(ErrorCodes.WALLET_PROVIDER_REQUEST_FAILED, "No nonce from the wallet provider")
        is DeviceKey -> failure(ErrorCodes.WALLET_PROVIDER_REQUEST_FAILED, "The device key is not available: ${cause.message}")
        is Integrity -> failure(ErrorCodes.WALLET_PROVIDER_REQUEST_FAILED, "Play Integrity failed: ${cause.message}")
        BodyNotSerialisable -> failure(ErrorCodes.WALLET_PROVIDER_REQUEST_FAILED, "The request body could not be made")
        SigningFailed -> failure(ErrorCodes.WALLET_PROVIDER_REQUEST_FAILED, "The request could not be signed")
    }

    private fun failure(code: Int, description: String) =
        ErrorResponse(error = code, errorDescription = description)
}
