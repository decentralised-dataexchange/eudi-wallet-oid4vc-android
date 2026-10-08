package com.ewc.eudi_wallet_oidc_android.services.tokenRefresh

import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedRefreshTokenResponse
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall
import com.ewc.eudi_wallet_oidc_android.services.utils.DPoPProofService
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletUnitAttestationHeaders
import com.nimbusds.jose.jwk.ECKey

class TokenRefreshService : TokenRefreshInterface {

    /**
    Attempts to refresh an access token using a refresh token.

    @param tokenEndPoint The OAuth 2.0 token endpoint URL where the refresh request will be sent
    @param refreshToken The refresh token to be used for obtaining a new access token
    @param walletUnitAttestationJWT Wallet unit attestation (client attestation) when the token
    endpoint uses attestation-based client authentication; null otherwise. RFC 6749 section 6:
    a client with authentication requirements MUST authenticate on a refresh request exactly as
    it does at the token endpoint (section 3.2.1).
    @param walletUnitProofOfPossession Supplier of a fresh PoP for the attestation, called once per request
    @param dpopKey The key the tokens are DPoP-bound to. When provided, a DPoP proof is sent with the
    request (RFC 9449 §5), with one retry if the server answers with a DPoP-Nonce. Null sends no proof.
    @return WrappedRefreshTokenResponse? which contains either:
    - A successful token response with new access token and related data
    - An error response if the refresh operation fails
    - null if the operation cannot be completed
     */
    override suspend fun refreshToken(
        tokenEndPoint: String?,
        refreshToken: String?,
        walletUnitAttestationJWT: String?,
        walletUnitProofOfPossession: (() -> String?)?,
        dpopKey: ECKey?,
    ): WrappedRefreshTokenResponse? {

        val requestBody = if (refreshToken != null) {
            println("refreshToken is not null and generating new accessToken")
            mutableMapOf<String, String?>(
                "grant_type" to "refresh_token",
                "refresh_token" to refreshToken,
            ).apply {
                // Only if WalletUnitAttestationHeaders.clientId exists in your library version.
                WalletUnitAttestationHeaders.clientId(walletUnitAttestationJWT, null)
                    ?.let { this["client_id"] = it }
            }
        } else {
            mutableMapOf<String, String?>(
                "grant_type" to null,
                "refresh_token" to null,
            )
        }

        // Token endpoint proof: htm/htu only, no ath. The nonce is added on the retry.
        fun dpopProof(nonce: String?): String? = dpopKey?.let {
            DPoPProofService().generateDPoP(
                httpMethod = "POST",
                targetUri = tokenEndPoint ?: "",
                dpopKey = it,
                claims = nonce?.let { n -> mapOf("nonce" to n) }
            )
        }

        // Client attestation headers (OAuth-Client-Attestation / -PoP, fresh PoP per request)
        // plus the DPoP proof.
        fun requestHeaders(nonce: String?): Map<String, String> =
            WalletUnitAttestationHeaders.build(
                walletUnitAttestationJWT,
                walletUnitProofOfPossession?.invoke()
            ).toMutableMap().apply {
                dpopProof(nonce)?.let { this["DPoP"] = it }
            }

        // AnyStatus keeps the response headers on 4xx, which the DPoP-Nonce retry needs.
        var result = SafeApiCall.safeApiCallAnyStatus {
            ApiManager.api.getService()?.getRefreshTokenFromCode(
                tokenEndPoint ?: "",
                requestBody,
                requestHeaders(null)
            )
        }

        val dpopNonce = result.getOrNull()?.takeIf { !it.isSuccessful }?.headers()?.get("DPoP-Nonce")
        if (dpopKey != null && !dpopNonce.isNullOrEmpty()) {
            result = SafeApiCall.safeApiCallAnyStatus {
                ApiManager.api.getService()?.getRefreshTokenFromCode(
                    tokenEndPoint ?: "",
                    requestBody,
                    requestHeaders(dpopNonce)
                )
            }
        }

        var tokenResponse: WrappedRefreshTokenResponse? = null

        result.onSuccess { response ->
            if (response.isSuccessful) {
                tokenResponse = WrappedRefreshTokenResponse(tokenResponse = response.body())
            } else {
                tokenResponse = WrappedRefreshTokenResponse(
                    errorResponse = ErrorResponse(
                        error = response.code(),
                        errorDescription = try {
                            response.errorBody()?.string()
                        } catch (e: Exception) {
                            null
                        } ?: response.message()
                    )
                )
            }
        }.onFailure { e ->
            tokenResponse = WrappedRefreshTokenResponse(
                errorResponse = ErrorResponse(errorDescription = e.message ?: "Unknown error")
            )
        }

        return tokenResponse
    }
}