package com.ewc.eudi_wallet_oidc_android.services.issue.deferred

import com.google.gson.annotations.SerializedName

/**
 * The deferred credential request body, assembled once.
 *
 * Section 9.1: `transaction_id` is REQUIRED, `credential_identifier` MAY be included. The draft form
 * has no body at all -- it carries its handle in the Authorization header -- which is why
 * [DeferredTransaction.LegacyAcceptanceToken] produces null here rather than an empty object.
 *
 * Mirrors `DeferredRequestParameters` in the iOS SDK.
 */
internal data class DeferredRequestParameters(
    @SerializedName("transaction_id") val transactionId: String,
    @SerializedName("credential_identifier") val credentialIdentifier: String? = null,
) {
    companion object {

        /** Null when the transaction is a draft acceptance token, which sends an empty body. */
        fun build(
            transaction: DeferredTransaction,
            policy: DeferredRequestPolicy,
        ): DeferredRequestParameters? = when (transaction) {
            is DeferredTransaction.LegacyAcceptanceToken -> null

            is DeferredTransaction.TransactionId -> DeferredRequestParameters(
                transactionId = transaction.value,
                credentialIdentifier = transaction.credentialIdentifier
                    ?.takeIf { it.isNotBlank() && policy.sendCredentialIdentifier },
            )
        }
    }
}
