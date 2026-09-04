package com.ewc.eudi_wallet_oidc_android.services.issue.authorization.idtoken

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationUri
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.util.Date

/**
 * Answers an authorization server that asked for an ID token instead of authorizing directly.
 *
 * The server redirects with `response_type=id_token` and a `redirect_uri`; the wallet signs an ID
 * token whose audience is the request's `client_id` and which echoes the request's `nonce`, then
 * posts it back with the `state`.
 *
 * Lifted from `IssueService.processAuthorisationRequestUsingIdToken` **unchanged** -- same claims,
 * same 60-second lifetime, same `kid` derivation, same EdDSA and ES256 handling, and the redirect
 * still read only from a 302. It was public there but absent from `IssueServiceInterface`, so a
 * host could reach it only by inspecting a URL the SDK had already inspected; it is now one of the
 * authorization request's named outcomes.
 */
class IdTokenResponder {

    /**
     * @param location the redirect that asked for the ID token.
     * @return the redirect to continue with, or null when the server returned none.
     */
    suspend fun respond(
        wallet: WalletIdentity,
        authorisationEndPoint: String?,
        location: String?,
    ): String? {
        val did = wallet.did
        val subJwk = wallet.jwk
        fun param(name: String) = AuthorizationUri.queryParameter(location, name)

        val claimsSet = JWTClaimsSet.Builder()
            .issueTime(Date())
            .expirationTime(Date(Date().time + ID_TOKEN_LIFETIME_MS))
            .issuer(did)
            .subject(did)
            .audience(param("client_id") ?: authorisationEndPoint)
            .claim("nonce", param("nonce"))
            .build()

        val jwsHeader = JWSHeader
            .Builder(if (subJwk is OctetKeyPair) JWSAlgorithm.EdDSA else JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID("$did#${did?.replace("did:key:", "")}")
            .build()

        val jwt = SignedJWT(jwsHeader, claimsSet)
        jwt.sign(
            if (subJwk is OctetKeyPair) Ed25519Signer(subJwk) else ECDSASigner(subJwk as ECKey)
        )

        val result = SafeApiCall.safeApiCallResponse {
            ApiManager.api.getService()?.sendIdTokenForCode(
                url = param("redirect_uri") ?: "",
                idToken = jwt.serialize(),
                state = param("state") ?: "",
                contentType = "application/x-www-form-urlencoded",
            )
        }

        return result.fold(
            onSuccess = { response ->
                if (response.code() == 302) response.headers()["Location"] else null
            },
            onFailure = { error ->
                Logger.e(TAG, "ID token response failed: ${error.message}")
                null
            },
        )
    }

    private companion object {
        const val TAG = "IdTokenResponder"

        /** 60 seconds, as the previous implementation used. */
        const val ID_TOKEN_LIFETIME_MS = 60_000L
    }
}
