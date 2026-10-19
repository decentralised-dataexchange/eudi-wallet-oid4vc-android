package com.ewc.eudi_wallet_oidc_android.services.issue.credential

import com.ewc.eudi_wallet_oidc_android.models.CredentialResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.credentialResponseEncryption.CredentialEncryptionBuilder
import com.google.gson.Gson
import okhttp3.ResponseBody
import retrofit2.Response

/**
 * Reads a 2xx credential response into a [CredentialOutcome].
 *
 * Extracted from `CredentialRequestResolver` because section 9.2 makes the **Deferred** Credential
 * Response the same shape as the Credential Response -- "the Deferred Credential Response ... MAY
 * itself be deferred again" -- so the credential leg and the deferred leg read the same body, and
 * re-issuance reaches it through the credential leg. Three copies of this is how the plural
 * `credentials` array came to be honoured in one place and dropped in the others.
 *
 * Section 8.3 and 9.2.
 */
internal object CredentialResponseReader {

    /**
     * @param encryption the response key, when the issuer encrypted the body (section 10).
     * @param fallbackTransactionId the handle the caller is already polling with, reused when a
     *   non-conformant issuer defers without naming one -- see the `interval` branch below. Only
     *   the deferred leg passes it, and only when its policy allows: on a first credential request
     *   there is no prior handle, so there is nothing to fall back to.
     * @throws CredentialRequestException.Unusable when the body cannot be read at all.
     */
    fun read(
        response: Response<ResponseBody>,
        encryption: CredentialEncryption?,
        fallbackTransactionId: String? = null,
    ): CredentialOutcome {
        val raw = response.body()?.string()
        if (raw.isNullOrBlank()) {
            throw CredentialRequestException.Unusable("The issuer returned an empty credential response")
        }
        return readBody(raw, response.headers()["Content-Type"], encryption, fallbackTransactionId)
    }

    /** As [read], for a body already in hand. */
    fun readBody(
        raw: String,
        contentType: String?,
        encryption: CredentialEncryption?,
        fallbackTransactionId: String? = null,
    ): CredentialOutcome {
        val json = if (contentType.orEmpty().contains("application/jwt", ignoreCase = true)) {
            val ecKey = encryption?.responseKey?.ecKey
                ?: throw CredentialRequestException.Unusable(
                    "The issuer encrypted the response but no decryption key was supplied"
                )
            CredentialEncryptionBuilder().decryptJWE(raw, ecKey)
                ?: throw CredentialRequestException.Unusable(
                    "The encrypted credential response could not be decrypted"
                )
        } else {
            raw
        }

        val decoded = runCatching { Gson().fromJson(json, CredentialResponse::class.java) }
            .getOrNull()
            ?: throw CredentialRequestException.Unusable("The credential response is not valid JSON")

        // Draft issuers call the deferred handle `acceptance_token`; 1.0 calls it `transaction_id`.
        // Section 9.2: a deferred response may carry one again, so this is reached on both legs.
        val transactionId = decoded.transactionId?.takeIf { it.isNotBlank() }
            ?: decoded.acceptanceToken?.takeIf { it.isNotBlank() }
        if (transactionId != null) {
            return CredentialOutcome.Deferred(transactionId, decoded.interval)
        }

        // Section 8.3's `credentials` is an array. The previous implementation read index 0 and
        // dropped the rest -- at six call sites in the wallet.
        val credentials = buildList {
            decoded.credentials?.mapNotNull { it.credential }?.let { addAll(it) }
            if (isEmpty()) decoded.credential?.takeIf { it.isNotBlank() }?.let { add(it) }
        }
        if (credentials.isEmpty()) {
            // A shape 1.0 does not define. Section 9.3 signals a pending credential with 400 and
            // `issuance_pending`; section 9.2 makes `transaction_id` REQUIRED in a 200 that defers
            // again, and `interval` is not a member of the success response at all. An issuer met
            // in the field sends 200 with `interval` and nothing else, so read strictly this is
            // "neither a credential nor a transaction id" and polling stops on a credential that
            // is still coming.
            //
            // The caller decides whether to accept it -- DeferredRequestPolicy.acceptIntervalOnlyAsPending
            // withholds the fallback when it should not be. The `interval` still gates it here:
            // it is the only positive evidence the response means "come back later" rather than
            // "something went wrong".
            if (decoded.interval != null && fallbackTransactionId != null) {
                return CredentialOutcome.Deferred(fallbackTransactionId, decoded.interval)
            }
            throw CredentialRequestException.Unusable(
                "The issuer returned neither a credential nor a transaction id"
            )
        }

        return CredentialOutcome.Issued(
            credentials = credentials,
            notificationId = decoded.notificationId,
            cNonce = decoded.cNonce,
        )
    }
}
