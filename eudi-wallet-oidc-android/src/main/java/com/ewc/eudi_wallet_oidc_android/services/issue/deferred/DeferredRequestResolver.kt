package com.ewc.eudi_wallet_oidc_android.services.issue.deferred

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletAttestation
import com.ewc.eudi_wallet_oidc_android.services.issue.credential.CredentialEncryption
import com.ewc.eudi_wallet_oidc_android.services.issue.credential.CredentialOutcome
import com.ewc.eudi_wallet_oidc_android.services.issue.credential.CredentialRequestException
import com.ewc.eudi_wallet_oidc_android.services.issue.credential.CredentialResponseReader
import com.ewc.eudi_wallet_oidc_android.services.issue.credential.credentialTransportFailure
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.HttpCall
import com.ewc.eudi_wallet_oidc_android.services.utils.DPoPProofService
import com.ewc.eudi_wallet_oidc_android.services.utils.ErrorHandler
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse.JWEEncrypter
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.ResponseBody
import retrofit2.Response

/**
 * Asks the issuer for a credential it deferred: send the handle, read the answer.
 *
 * Returns the same [CredentialOutcome] as the credential request, because section 9.2 says the
 * Deferred Credential Response *is* the Credential Response -- and "MAY itself be deferred again",
 * which arrives here as [CredentialOutcome.Deferred] coming back out.
 *
 * What this can do that the two functions it replaces could not, all downstream of [HttpCall]
 * replacing `SafeApiCall`:
 *
 *  - tell `issuance_pending` from `invalid_transaction_id`. Both used to be a null and a `println`,
 *    so a wallet polled a permanently dead transaction until the credential's own expiry;
 *  - report the issuer's `interval` (section 9.3: "the minimum number of seconds the Wallet MUST
 *    wait"), instead of the caller guessing one;
 *  - answer RFC 9449's DPoP nonce challenge.
 *
 * Mirrors `DeferredRequestResolver` in the iOS SDK.
 */
class DeferredRequestResolver(
    private val policy: DeferredRequestPolicy = DeferredRequestPolicy.Default,
) {

    suspend fun resolve(
        session: IssuanceSession,
        token: TokenResponse,
        transaction: DeferredTransaction,
        attestation: WalletAttestation? = null,
        encryption: CredentialEncryption? = null,
        dpopNonce: String? = null,
    ): CredentialOutcome {
        val endpoint = session.issuerConfig?.deferredCredentialEndpoint
        if (endpoint.isNullOrBlank()) {
            return CredentialOutcome.Failed(
                CredentialRequestException.Unusable(
                    "This issuer deferred a credential but published no deferred credential endpoint"
                ).toErrorResponse()
            )
        }

        return try {
            send(endpoint, session, token, transaction, attestation, encryption, dpopNonce, true)
        } catch (e: CredentialRequestException) {
            Logger.e(TAG, "deferred credential request failed: ${e.message}")
            CredentialOutcome.Failed(e.toErrorResponse())
        } catch (e: Exception) {
            Logger.e(TAG, "deferred credential request failed unexpectedly", e)
            CredentialOutcome.Failed(
                CredentialRequestException.Unusable(
                    e.message ?: "The deferred credential request failed"
                ).toErrorResponse()
            )
        }
    }

    private suspend fun send(
        endpoint: String,
        session: IssuanceSession,
        token: TokenResponse,
        transaction: DeferredTransaction,
        attestation: WalletAttestation?,
        encryption: CredentialEncryption?,
        dpopNonce: String?,
        allowRetry: Boolean,
    ): CredentialOutcome {
        val parameters = DeferredRequestParameters.build(transaction, policy)

        // The draft form authenticates with the handle itself and sends nothing; 1.0 uses the
        // access token from the credential request and names the transaction in the body.
        val accessToken = when (transaction) {
            is DeferredTransaction.LegacyAcceptanceToken -> transaction.value
            is DeferredTransaction.TransactionId -> token.accessToken.orEmpty()
        }

        val dpopKey = attestation?.dpopKey
        val dpop = dpopKey
            ?.takeIf { transaction is DeferredTransaction.TransactionId }
            ?.let {
                DPoPProofService().generateDPoP(
                    httpMethod = "POST",
                    targetUri = endpoint,
                    dpopKey = it,
                    claims = buildMap {
                        // RFC 9449 section 4.2: the deferred endpoint is a resource server too.
                        put("ath", DPoPProofService().computeAccessTokenHash(accessToken))
                        dpopNonce?.let { value -> put("nonce", value) }
                    },
                )
            }
        val authorization = if (dpop != null) "DPoP $accessToken" else "Bearer $accessToken"

        Logger.d(
            TAG,
            "deferred request: endpoint=$endpoint shape=${describe(transaction)} " +
                "auth=${if (dpop != null) "DPoP" else "Bearer"} " +
                "encryptedRequest=${encryption?.requestEncryptionRequired == true}",
        )

        val response: Response<ResponseBody> = HttpCall.call(::credentialTransportFailure) {
            perform(endpoint, parameters, authorization, dpop, encryption)
        }

        if (response.isSuccessful) {
            return CredentialResponseReader.read(
                response,
                encryption,
                // Only offered when the policy allows it; see acceptIntervalOnlyAsPending.
                fallbackTransactionId = transaction.value
                    .takeIf { policy.acceptIntervalOnlyAsPending },
            )
        }

        val body = HttpCall.errorBody(response)
        val error = ErrorHandler.processError(body, response.code())
        val issuedDPoPNonce = response.headers()["DPoP-Nonce"]

        if (allowRetry && policy.retryOnDPoPNonce && dpopKey != null &&
            response.code() == 400 && error?.errorCode == USE_DPOP_NONCE && !issuedDPoPNonce.isNullOrBlank()
        ) {
            Logger.d(TAG, "deferred endpoint asked for a DPoP nonce; retrying once")
            return send(
                endpoint, session, token, transaction, attestation, encryption,
                issuedDPoPNonce, allowRetry = false,
            )
        }

        // Section 9.3: the credential is not ready, and this is not a failure. Reporting it as one
        // is what made a wallet stop polling a transaction that was still coming.
        if (error?.errorCode == ISSUANCE_PENDING) {
            val interval = intervalFrom(body)
            Logger.d(TAG, "issuance still pending; the issuer asks for ${interval ?: "no"} seconds")
            return CredentialOutcome.Deferred(transaction.value, interval)
        }

        Logger.e(
            TAG,
            "deferred endpoint ${response.code()} error=${error?.errorCode ?: error?.errorDescription}",
        )
        return CredentialOutcome.Failed(
            error ?: CredentialRequestException.Rejected(response.code(), body).toErrorResponse()
        )
    }

    private suspend fun perform(
        endpoint: String,
        parameters: DeferredRequestParameters?,
        authorization: String,
        dpop: String?,
        encryption: CredentialEncryption?,
    ): Response<ResponseBody>? {
        // The draft form sends an empty object; 1.0 sends the transaction.
        val payloadJson = parameters?.let { Gson().toJson(it) } ?: "{}"

        // Section 10: the client "MUST" encrypt when the issuer sets `encryption_required`.
        if (encryption?.requestEncryptionRequired == true && parameters != null) {
            val jwk = encryption.request?.jwk
                ?: throw CredentialRequestException.Unusable(
                    "This issuer requires an encrypted deferred request but published no key"
                )
            val type = object : TypeToken<Map<String, Any?>>() {}.type
            val payload: Map<String, Any?> = Gson().fromJson(payloadJson, type)
            val body = JWEEncrypter().encrypt(payload = payload, jwk = jwk)
                .toRequestBody("application/jwt".toMediaType())
            return ApiManager.api.getService()
                ?.requestDeferredCredential(endpoint, "application/jwt", authorization, dpop, body)
        }

        val body = payloadJson.toRequestBody("application/json".toMediaType())
        return ApiManager.api.getService()
            ?.requestDeferredCredential(endpoint, "application/json", authorization, dpop, body)
    }

    /** Section 9.3's `interval`, when the issuer named one. */
    private fun intervalFrom(body: String?): Int? = runCatching {
        org.json.JSONObject(body ?: return null).optInt("interval").takeIf { it > 0 }
    }.getOrNull()

    private fun describe(transaction: DeferredTransaction) = when (transaction) {
        is DeferredTransaction.TransactionId -> "transaction_id"
        is DeferredTransaction.LegacyAcceptanceToken -> "acceptance_token (draft)"
    }

    private companion object {
        const val TAG = "DeferredCredentialRequest"
        const val USE_DPOP_NONCE = "use_dpop_nonce"
        const val ISSUANCE_PENDING = "issuance_pending"
    }
}
