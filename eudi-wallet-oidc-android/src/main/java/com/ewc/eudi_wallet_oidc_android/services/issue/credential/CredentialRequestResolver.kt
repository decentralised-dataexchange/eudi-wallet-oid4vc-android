package com.ewc.eudi_wallet_oidc_android.services.issue.credential

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.CredentialRequest
import okhttp3.ResponseBody
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletAttestation
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.ewc.eudi_wallet_oidc_android.services.issue.credential.proof.CredentialProofFactory
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.HttpCall
import com.ewc.eudi_wallet_oidc_android.services.nonceRequest.NonceService
import com.ewc.eudi_wallet_oidc_android.services.utils.DPoPProofService
import com.ewc.eudi_wallet_oidc_android.services.utils.ErrorHandler
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse.JWEEncrypter
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import retrofit2.Response

/**
 * Asks the issuer for a credential: obtain a nonce, sign a proof, send, read the answer.
 *
 * A pipeline rather than a registry -- the token response decides the request's shape, so there is
 * nothing to select at runtime.
 *
 * Three things this can do that the previous implementation could not, all downstream of
 * [HttpCall] replacing `SafeApiCall`, which discarded the status code and every header before the
 * caller saw them:
 *
 *  - a rejection carries the issuer's own `error` code and the HTTP status;
 *  - section 8.3.1's stale-nonce retry, since the fresh `c_nonce` arrives in the error body;
 *  - RFC 9449's DPoP nonce retry, since that one arrives in a header.
 */
class CredentialRequestResolver(
    private val policy: CredentialRequestPolicy = CredentialRequestPolicy.Default,
) {

    /**
     * @param nonce overrides the `c_nonce`. Left null the resolver obtains one itself, from the
     *   Nonce Endpoint when the issuer publishes one (section 7 -- it is unauthenticated) and
     *   otherwise from the token response. Callers used to do this, which is why a single nonce was
     *   reused for every credential in a multi-credential offer.
     */
    suspend fun resolve(
        session: IssuanceSession,
        wallet: WalletIdentity,
        token: TokenResponse,
        subject: CredentialSubject,
        issuer: String?,
        attestation: WalletAttestation? = null,
        keyAttestation: String? = null,
        encryption: CredentialEncryption? = null,
        nonce: String? = null,
        dpopNonce: String? = null,
    ): CredentialOutcome {
        val endpoint = session.issuerConfig?.credentialEndpoint
        if (endpoint.isNullOrBlank()) {
            return failed(CredentialRequestException.NoCredentialEndpoint())
        }

        return try {
            send(
                endpoint = endpoint,
                session = session,
                wallet = wallet,
                token = token,
                subject = subject,
                issuer = issuer,
                attestation = attestation,
                keyAttestation = keyAttestation,
                encryption = encryption,
                nonce = nonce ?: obtainNonce(session, token),
                dpopNonce = dpopNonce,
                allowRetry = true,
            )
        } catch (e: CredentialRequestException) {
            Logger.e(TAG, "credential request failed: ${e.message}")
            CredentialOutcome.Failed(e.toErrorResponse())
        } catch (e: Exception) {
            Logger.e(TAG, "credential request failed unexpectedly", e)
            CredentialOutcome.Failed(
                CredentialRequestException.Unusable(
                    e.message ?: "The credential request failed"
                ).toErrorResponse()
            )
        }
    }

    /**
     * Section 7: a Credential Issuer that requires `c_nonce` values "MUST offer a Nonce Endpoint",
     * and that endpoint "is not a protected resource". Draft issuers instead return `c_nonce` with
     * the token, so that is the fallback.
     */
    private suspend fun obtainNonce(session: IssuanceSession, token: TokenResponse): String? {
        val nonceEndpoint = session.issuerConfig?.nonceEndpoint
        if (!nonceEndpoint.isNullOrBlank()) {
            NonceService().fetchNonce(token.accessToken, nonceEndpoint)
                ?.takeIf { it.isNotBlank() }
                ?.let { return it }
            Logger.d(TAG, "the nonce endpoint returned nothing; falling back to the token's c_nonce")
        }
        return token.cNonce
    }

    private suspend fun send(
        endpoint: String,
        session: IssuanceSession,
        wallet: WalletIdentity,
        token: TokenResponse,
        subject: CredentialSubject,
        issuer: String?,
        attestation: WalletAttestation?,
        keyAttestation: String?,
        encryption: CredentialEncryption?,
        nonce: String?,
        dpopNonce: String?,
        allowRetry: Boolean,
    ): CredentialOutcome {
        val proof = CredentialProofFactory.create(
            session = session,
            wallet = wallet,
            issuer = issuer,
            nonce = nonce,
            subject = subject,
            keyAttestation = keyAttestation,
        )

        val request = CredentialRequestParameters.build(
            subject = subject,
            proof = proof,
            session = session,
            encryption = encryption,
            policy = policy,
        )

        Logger.d(
            TAG,
            "credential request: endpoint=$endpoint subject=${describe(subject)} " +
                "proofs=${request.proofs != null} nonce=${if (nonce.isNullOrBlank()) "none" else "present"} " +
                "keyAttestation=${keyAttestation != null} encryptedRequest=${encryption?.requestEncryptionRequired == true}",
        )

        val accessToken = token.accessToken.orEmpty()
        val dpopKey = attestation?.dpopKey
        val dpop = dpopKey?.let {
            DPoPProofService().generateDPoP(
                httpMethod = "POST",
                targetUri = endpoint,
                dpopKey = it,
                claims = buildMap {
                    put("ath", DPoPProofService().computeAccessTokenHash(accessToken))
                    dpopNonce?.let { value -> put("nonce", value) }
                },
            )
        }
        val authorization = if (dpop != null) "DPoP $accessToken" else "Bearer $accessToken"

        val response: Response<ResponseBody> = HttpCall.call(::credentialTransportFailure) {
            perform(endpoint, request, authorization, dpop, encryption)
        }

        val issuedDPoPNonce = response.headers()["DPoP-Nonce"]

        if (response.isSuccessful) {
            return CredentialResponseReader.read(response, encryption)
        }

        val body = HttpCall.errorBody(response)
        val error = ErrorHandler.processError(body, response.code())

        // RFC 9449 section 8, the same challenge the token endpoint answers -- the credential
        // endpoint has never handled it.
        if (allowRetry && policy.retryOnDPoPNonce && dpopKey != null &&
            response.code() == 400 && error?.errorCode == USE_DPOP_NONCE && !issuedDPoPNonce.isNullOrBlank()
        ) {
            Logger.d(TAG, "credential endpoint asked for a DPoP nonce; retrying once")
            return send(
                endpoint, session, wallet, token, subject, issuer, attestation, keyAttestation,
                encryption, nonce, issuedDPoPNonce, allowRetry = false,
            )
        }

        // Section 8.3.1: "The Credential Issuer MAY return a new `c_nonce` value in an error
        // response" -- so a rejected proof is often recoverable by signing again with it.
        val freshNonce = freshNonceFrom(body)
        if (allowRetry && policy.retryOnStaleNonce &&
            (error?.errorCode == INVALID_PROOF || error?.errorCode == INVALID_NONCE) &&
            !freshNonce.isNullOrBlank()
        ) {
            Logger.d(TAG, "issuer rejected the proof and supplied a fresh nonce; retrying once")
            return send(
                endpoint, session, wallet, token, subject, issuer, attestation, keyAttestation,
                encryption, freshNonce, dpopNonce, allowRetry = false,
            )
        }

        // A 500 rarely carries a usable body, so the request that produced it is the evidence.
        // Bodies are only logged at debug; the proof and any key attestation are sent to this
        // issuer anyway, and neither is a wallet secret.
        Logger.e(TAG, "credential endpoint ${response.code()} error=${error?.errorCode ?: error?.errorDescription}")
        Logger.e(TAG, "credential endpoint ${response.code()} body=${body ?: "<empty>"}")
        Logger.d(TAG, "the request it refused: ${Gson().toJson(request)}")
        return CredentialOutcome.Failed(
            error ?: CredentialRequestException.Rejected(response.code(), body).toErrorResponse()
        )
    }

    private suspend fun perform(
        endpoint: String,
        request: CredentialRequest,
        authorization: String,
        dpop: String?,
        encryption: CredentialEncryption?,
    ): Response<ResponseBody>? {
        // Section 10: the client "MUST" encrypt when the issuer sets `encryption_required`.
        if (encryption?.requestEncryptionRequired == true) {
            val jwk = encryption.request?.jwk
                ?: throw CredentialRequestException.Unusable(
                    "This issuer requires an encrypted credential request but published no key"
                )
            val type = object : TypeToken<Map<String, Any?>>() {}.type
            val payload: Map<String, Any?> = Gson().fromJson(Gson().toJson(request), type)
            val body = JWEEncrypter().encrypt(payload = payload, jwk = jwk)
                .toRequestBody("application/jwt".toMediaType())
            return ApiManager.api.getService()
                ?.getCredentialEncrypted(endpoint, "application/jwt", authorization, dpop, body)
        }
        return ApiManager.api.getService()
            ?.getCredential(endpoint, "application/json", authorization, dpop, request)
    }

    /** The `c_nonce` an issuer may put in an error response, section 8.3.1. */
    private fun freshNonceFrom(body: String?): String? = runCatching {
        org.json.JSONObject(body ?: return null).optString("c_nonce").takeIf { it.isNotBlank() }
    }.getOrNull()

    private fun describe(subject: CredentialSubject) = when (subject) {
        is CredentialSubject.ByIdentifier -> "credential_identifier=${subject.credentialIdentifier}"
        is CredentialSubject.ByConfiguration -> "credential_configuration_id=${subject.credentialConfigurationId}"
        is CredentialSubject.LegacyFormat -> "format=${subject.format} vct=${subject.vct} doctype=${subject.docType}"
    }

    private fun failed(e: CredentialRequestException) = CredentialOutcome.Failed(e.toErrorResponse())

    private companion object {
        const val TAG = "CredentialRequest"
        const val USE_DPOP_NONCE = "use_dpop_nonce"
        const val INVALID_PROOF = "invalid_proof"
        const val INVALID_NONCE = "invalid_nonce"
    }
}
