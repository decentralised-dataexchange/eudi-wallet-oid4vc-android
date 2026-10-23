package com.ewc.eudi_wallet_oidc_android.services.verification.transaction

/**
 * The TS12 strong customer authentication transaction types: payment, login_risk,
 * account_access and emandate, as a `urn:eudi:sca:` URN or as an HTTPS transaction-data-type URL.
 * The EWC `payment_data` type and the QES types are not SCA, and must not carry `response_mode`
 * and `amr` in the key binding JWT.
 */
object StrongCustomerAuthentication {

    private val URL_TYPES = listOf("payment", "login_risk", "account_access", "emandate")

    fun isScaType(type: String): Boolean =
        type.contains("urn:eudi:sca:") || URL_TYPES.any { type.contains("transaction-data-type/$it") }

    fun requested(entries: List<TransactionDataEntry>): Boolean = entries.any { isScaType(it.type) }
}
