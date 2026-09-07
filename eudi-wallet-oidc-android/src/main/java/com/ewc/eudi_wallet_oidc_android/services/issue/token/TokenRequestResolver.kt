package com.ewc.eudi_wallet_oidc_android.services.issue.token

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedTokenResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletAttestation
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.HttpCall
import com.ewc.eudi_wallet_oidc_android.services.utils.DPoPProofService
import com.ewc.eudi_wallet_oidc_android.services.utils.ErrorHandler
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletUnitAttestationHeaders
import com.nimbusds.jose.jwk.ECKey
import retrofit2.Response

/**
 * Exchanges a code for an access token: build the body once, send it, read the answer.
 *
 * No transport registry here, unlike the authorization request -- the *offer* decides the grant, so
 * there is nothing to select at runtime and a registry would be the pattern applied out of habit.
 *
 * Two things this fixes that the previous implementation could not, both because
 * `SafeApiCall` discards the status code and every header before the caller sees them:
 *
 *  - a 4xx now reports the server's own `error` code and HTTP status, where before it arrived as a
 *    bare message and `ErrorResponse.httpStatus` was always null;
 *  - the DPoP nonce challenge (RFC 9449 section 8) can be seen at all, since it is carried in a
 *    `DPoP-Nonce` **header** on a 400.
 */
class TokenRequestResolver(
    private val policy: TokenRequestPolicy = TokenRequestPolicy.Default,
) {

    /**
     * @param authorizationDetails the value the authorization request sent, forwarded only when
     *   [TokenRequestPolicy.sendAuthorizationDetails] is on.
     * @param dpopNonce a nonce the authorization server supplied earlier. RFC 9449 section 8.2: the
     *   client "MUST use the new nonce value supplied for the next token request and for all
     *   subsequent token requests until the authorization server supplies a new nonce".
     */
    suspend fun resolve(
        session: IssuanceSession,
        wallet: WalletIdentity,
        attestation: WalletAttestation? = null,
        grant: TokenGrant,
        authorizationDetails: String? = null,
        dpopNonce: String? = null,
    ): WrappedTokenResponse {
        val tokenEndpoint = session.authConfig?.tokenEndpoint
        if (tokenEndpoint.isNullOrBlank()) {
            return failure("This issuer's authorization server declared no token endpoint")
        }

        // Section 6.1: a Transaction Code is required by the *offer*, not by whether the caller has
        // one. Failing here saves a round trip and says something the user can act on.
        if (grant is TokenGrant.PreAuthorized &&
            session.requiresTransactionCode &&
            grant.txCode.isNullOrBlank()
        ) {
            return failure("This offer requires a transaction code")
        }

        val parameters = TokenRequestParameters.build(
            session = session,
            wallet = wallet,
            attestation = attestation,
            grant = grant,
            authorizationDetails = authorizationDetails,
            policy = policy,
        )

        // TS3: the DPoP key must be the one the attestation names in `cnf`. A mismatch is
        // rejected as invalid_client_attestation with nothing in the response to say why, so say it
        // here. Replaces the unconditional android.util.Log block this function used to carry.
        attestation?.dpopKeyMatchesAttestation?.let { matches ->
            if (!matches) Logger.e(TAG, "the DPoP key is not the one the wallet attestation names in cnf")
        }

        return try {
            send(tokenEndpoint, parameters, attestation, attestation?.dpopKey, dpopNonce, allowRetry = true)
        } catch (e: TokenRequestException) {
            Logger.e(TAG, "token request failed: ${e.message}")
            WrappedTokenResponse(errorResponse = e.toErrorResponse())
        } catch (e: Exception) {
            // Nothing below should throw anything else; if it does, the caller still gets a reason
            // rather than an exception escaping the SDK.
            Logger.e(TAG, "token request failed unexpectedly", e)
            failure(e.message ?: "The token request failed")
        }
    }

    private suspend fun send(
        tokenEndpoint: String,
        parameters: TokenRequestParameters,
        attestation: WalletAttestation?,
        dpopKey: ECKey?,
        dpopNonce: String?,
        allowRetry: Boolean,
    ): WrappedTokenResponse {
        val dpop = dpopKey?.let {
            DPoPProofService().generateDPoP(
                httpMethod = "POST",
                targetUri = tokenEndpoint,
                dpopKey = it,
                // The nonce goes in as an ordinary claim; the signing service already takes a map,
                // so nothing about DPoP proof generation changes for this.
                claims = dpopNonce?.let { nonce -> mapOf("nonce" to nonce) },
            )
        }

        val headers = WalletUnitAttestationHeaders.build(
            attestation?.attestationJwt,
            attestation?.proofOfPossession,
        ).apply {
            if (!dpop.isNullOrEmpty()) this["DPoP"] = dpop
        }

        val response: Response<TokenResponse> = HttpCall.call(::tokenTransportFailure) {
            ApiManager.api.getService()?.getAccessTokenFromCode(
                tokenEndpoint,
                parameters.toMap(),
                headers,
            )
        }

        // RFC 9449 section 8.2: a nonce may also arrive on a success, rotating the one in use.
        val issuedNonce = response.headers()["DPoP-Nonce"]

        if (response.isSuccessful) {
            return WrappedTokenResponse(
                tokenResponse = response.body(),
                legalPidAttestation = response.headers()["legal-pid-attestation"],
                legalPidAttestationPoP = response.headers()["legal-pid-attestation-pop"],
                dpop = dpop,
                dpopNonce = issuedNonce ?: dpopNonce,
            )
        }

        val body = HttpCall.errorBody(response)
        val error = ErrorHandler.processError(body, response.code())

        // RFC 9449 section 8: `400` + `use_dpop_nonce` + a `DPoP-Nonce` header. Exactly once.
        val demandsNonce = response.code() == 400 &&
            error?.errorCode == USE_DPOP_NONCE &&
            !issuedNonce.isNullOrBlank()
        if (demandsNonce && allowRetry && policy.retryOnDPoPNonce && dpopKey != null) {
            Logger.d(TAG, "token endpoint asked for a DPoP nonce; retrying once")
            return send(tokenEndpoint, parameters, attestation, dpopKey, issuedNonce, allowRetry = false)
        }

        Logger.e(TAG, "token endpoint ${response.code()} error=${error?.errorCode ?: error?.errorDescription}")
        return WrappedTokenResponse(
            errorResponse = error ?: ErrorResponse(
                error = -1,
                errorDescription = "The token request was refused (HTTP ${response.code()})",
                httpStatus = response.code(),
            ),
            dpopNonce = issuedNonce,
        )
    }

    private fun failure(reason: String) = WrappedTokenResponse(
        errorResponse = ErrorResponse(error = -1, errorDescription = reason),
    )

    private companion object {
        const val TAG = "TokenRequest"
        const val USE_DPOP_NONCE = "use_dpop_nonce"
    }
}

/** Why a token request could not be completed. Internal: the resolver converts it into a reason. */
internal class TokenRequestException(message: String) : Exception(message) {
    fun toErrorResponse() = ErrorResponse(error = -1, errorDescription = message)
}

/** @see com.ewc.eudi_wallet_oidc_android.services.network.HttpCall */
internal fun tokenTransportFailure(detail: String?): Exception =
    TokenRequestException(detail ?: "The token request failed")
