package com.ewc.eudi_wallet_oidc_android.services.issue.credential.proof

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.Credentials
import com.ewc.eudi_wallet_oidc_android.services.issue.IssueService
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.ewc.eudi_wallet_oidc_android.services.issue.credential.CredentialRequestException
import com.ewc.eudi_wallet_oidc_android.services.issue.credential.CredentialRequestParameters
import com.ewc.eudi_wallet_oidc_android.services.issue.credential.CredentialSubject
import com.ewc.eudi_wallet_oidc_android.services.utils.ProofService
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.util.Date

/**
 * Builds the `openid4vci-proof+jwt` that proves possession of the key a credential will be bound to.
 *
 * Moved here from `services/utils/ProofService` because the credential request is the only thing
 * that uses it -- the same reasoning that put `IdTokenResponder` under `authorization/idtoken/`.
 * `ProofService` keeps `getCryptographicBindingMethodSupported`, which reads issuer metadata and
 * which `data-wallet-android` calls directly; moving that would have broken the app for a function
 * that has nothing to do with building a proof.
 *
 * Section 8.2 and Appendix F: `typ` is `openid4vci-proof+jwt`; `aud` is the Credential Issuer
 * Identifier; `iat` is REQUIRED; `nonce` is REQUIRED when the issuer publishes a Nonce Endpoint;
 * and a key attestation travels in the `key_attestation` JOSE **header**, not in the body.
 */
internal object CredentialProofFactory {

    private const val TAG = "CredentialProof"

    /** 24 hours, in **seconds**. */
    private const val LIFETIME_SECONDS = 86_400L

    /**
     * @param nonce the issuer's `c_nonce`. Required when [IssuanceSession] shows a nonce endpoint.
     * @param keyAttestation the wallet-provider attestation, when one is owed. Null attaches none.
     * @throws CredentialRequestException
     */
    fun create(
        session: IssuanceSession,
        wallet: WalletIdentity,
        nonce: String?,
        subject: CredentialSubject,
        keyAttestation: String? = null,
    ): String {
        val credentialType = CredentialRequestParameters.configurationIdOf(subject)
        // Section 8.2: the nonce is REQUIRED when a Nonce Endpoint exists. Omitting it silently --
        // which is what a null nonce used to do -- produces `invalid_proof` a round trip later,
        // with nothing in the response saying which of the proof's parts was wrong.
        if (nonce.isNullOrBlank() && !session.issuerConfig?.nonceEndpoint.isNullOrBlank()) {
            throw CredentialRequestException.NoNonce()
        }

        val subJwk = wallet.jwk
        val claims = JWTClaimsSet.Builder()
            // Fresh iat: the proof is replay-bound by the issuer c_nonce and, like DPoP, can be
            // rejected for a stale one. Only the client-attestation PoP needs the WalletClock
            // backdate.
            .issueTime(Date())
            // Was `Date(Date().time + 86400)` -- Date.time is milliseconds, so the proof expired
            // 86.4 seconds after it was issued rather than the day the constant intends. A
            // multi-credential offer is issued sequentially and could outlive its own proof.
            .expirationTime(Date(System.currentTimeMillis() + LIFETIME_SECONDS * 1000))
            .issuer(wallet.did)
            .audience(session.issuerConfig?.credentialIssuer ?: "")
            .apply { nonce?.takeIf { it.isNotBlank() }?.let { claim("nonce", it) } }
            .build()

        val header = JWSHeader.Builder(algorithmFor(session, subJwk, credentialType))
            .type(JOSEObjectType("openid4vci-proof+jwt"))
            .apply {
                val bindingMethod = bindingMethodFor(session, subject.offerCredential)
                when {
                    bindingMethod?.lowercase()?.startsWith("did") == true ->
                        keyID(keyIdFor(bindingMethod, subJwk, wallet.did))

                    subject.offerCredential?.trustFramework != null ->
                        keyID(keyIdFor(bindingMethod, subJwk, wallet.did))

                    else -> jwk(subJwk?.toPublicJWK())
                }
                // ARF TS3 v1.5: the key attestation travels in this header parameter.
                keyAttestation?.takeIf { it.isNotEmpty() }?.let { customParam("key_attestation", it) }
            }
            .build()

        val signer = when (subJwk) {
            is OctetKeyPair -> Ed25519Signer(subJwk)
            is ECKey -> ECDSASigner(subJwk)
            else -> throw CredentialRequestException.ProofFailed(
                "The wallet's binding key is neither an EC key nor an Octet key pair"
            )
        }

        return try {
            SignedJWT(header, claims).apply { sign(signer) }.serialize()
        } catch (e: Exception) {
            Logger.e(TAG, "could not sign the credential proof", e)
            throw CredentialRequestException.ProofFailed("The credential proof could not be signed")
        }
    }

    /**
     * The signature algorithm.
     *
     * **The key decides this, not the metadata** -- a P-256 key can only produce ES256 and an
     * Ed25519 key only EdDSA, so `cryptographic_suites_supported` cannot select an algorithm, it
     * can only reveal that the caller's key is one the issuer will not accept. That is worth
     * saying out loud rather than discovering from a rejected credential request.
     *
     * `getCryptoFromIssuerConfig` has been on `IssueServiceInterface` and implemented all along,
     * and called from nowhere; this is the first thing to read it.
     */
    private fun algorithmFor(session: IssuanceSession, subJwk: JWK?, credentialType: String?): JWSAlgorithm {
        val algorithm = if (subJwk is OctetKeyPair) JWSAlgorithm.EdDSA else JWSAlgorithm.ES256

        val declared = runCatching {
            IssueService().getCryptoFromIssuerConfig(session.issuerConfig, credentialType)
        }.getOrNull().orEmpty()

        if (declared.isNotEmpty() && declared.none { it.equals(algorithm.name, ignoreCase = true) }) {
            Logger.e(
                TAG,
                "the binding key signs ${algorithm.name}, which this issuer does not list: $declared",
            )
        }
        return algorithm
    }

    /**
     * The binding method the issuer declares for **this** credential.
     *
     * Takes the offer entry rather than searching for it: the previous version recovered an index
     * by matching a type string and fell back to the first credential, which silently produces a
     * proof bound the wrong way on a multi-credential offer. A one-element list is exactly the
     * lookup `getCryptographicBindingMethodSupported` performs, without the search.
     */
    private fun bindingMethodFor(session: IssuanceSession, credential: Credentials?): String? {
        val supported = session.issuerConfig?.credentialsSupported ?: return null
        if (credential == null) return null
        val methods = runCatching {
            ProofService().getCryptographicBindingMethodSupported(supported, arrayListOf(credential), 0)
        }.getOrNull()
        return methods?.firstOrNull { it.startsWith("did") } ?: methods?.firstOrNull()
    }

    private fun keyIdFor(bindingMethod: String?, subJwk: JWK?, did: String?): String = when (bindingMethod) {
        "did:jwk" -> subJwk?.toPublicJWK()?.toJSONString()
            ?.let { "did:jwk:${Base64URL.encode(it)}" }.orEmpty()

        // RFC 7638. This used to be `subJwk.keyID` on Android and a SHA-256 over the whole sorted
        // JWK on iOS -- two different values for the same binding method, neither of them the
        // standard thumbprint, which is computed over the required members only.
        "jwk" -> subJwk?.toPublicJWK()?.computeThumbprint()?.toString().orEmpty()

        else -> "$did#${did?.replace("did:key:", "")}"
    }
}
