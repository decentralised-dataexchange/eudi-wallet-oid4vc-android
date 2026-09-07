package com.ewc.eudi_wallet_oidc_android.services.issue.authorization

import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.nimbusds.jose.jwk.ECKey
import org.json.JSONObject
import java.util.Base64
import com.nimbusds.jose.jwk.JWK

/**
 * Everything steps 1 and 2 established about this issuance.
 *
 * These three always travel together and always come from the same place -- the offer resolver and
 * the discovery resolvers -- so passing them as one value removes three parameters and makes it
 * impossible to hand in an issuer configuration belonging to a different offer.
 */
data class IssuanceSession(
    val credentialOffer: CredentialOffer?,
    val issuerConfig: IssuerWellKnownConfiguration?,
    val authConfig: AuthorisationServerWellKnownConfiguration?,
) {
    /** Which revision of the offer this is: 1 for pre-1.0 drafts, 2 for OpenID4VCI 1.0. */
    val offerVersion: Int? get() = credentialOffer?.version

    /**
     * The `issuer_state` the offer carried, or null.
     *
     * Section 4.1.1: on receiving it "the Wallet ... MUST include it in the subsequent
     * Authorization Request". Null rather than blank, so it is omitted rather than sent empty.
     */
    val issuerState: String?
        get() = credentialOffer?.grants?.authorizationCode?.issuerState?.takeIf { it.isNotBlank() }

    /**
     * Whether the offer obliges the wallet to send a Transaction Code with the token request.
     *
     * Section 6.1: the code "MUST be present if a `tx_code` object was present in the Credential
     * Offer (**including if the object was empty**)". So the test is the presence of the object,
     * not whether it declares a length -- and not whether the caller happens to have a code.
     *
     * Ask this before prompting the user: an empty `"tx_code": {}` still means a code is required,
     * and Gson yields a non-null [com.ewc.eudi_wallet_oidc_android.models.TxCode] for it.
     */
    val requiresTransactionCode: Boolean
        get() = credentialOffer?.grants?.preAuthorizationCode?.transactionCode != null
}

/** The wallet's own key identity. `jwk` signs the ID token when one is asked for. */
data class WalletIdentity(
    val did: String?,
    val jwk: JWK?,
)

/**
 * The wallet unit attestation and the keys bound to it.
 *
 * The attestation and its proof of possession are meaningless apart, and ARF TS3 requires the DPoP
 * key to be the one named in the attestation's `cnf` claim -- so all three belong in one value
 * where that can be checked, rather than as three parameters a caller can mismatch.
 */
data class WalletAttestation(
    val attestationJwt: String?,
    val proofOfPossession: String?,
    val dpopKey: ECKey? = null,
) {
    /**
     * Whether [dpopKey] is the key the attestation names in its `cnf` claim, as ARF TS3 requires.
     *
     * Null when there is nothing to compare -- no key, no attestation, or a `cnf` this cannot be
     * parsed. A `false` is the shape of failure that produces `invalid_client_attestation` from the
     * authorization server, and it is invisible in the response, so it is worth logging before the
     * request goes out.
     */
    val dpopKeyMatchesAttestation: Boolean?
        get() {
            val thumbprint = runCatching { dpopKey?.computeThumbprint()?.toString() }.getOrNull()
                ?: return null
            val cnf = runCatching {
                val payload = attestationJwt?.substringBefore('~')?.split('.')?.getOrNull(1)
                    ?: return@runCatching null
                // java.util rather than android.util: the latter is stubbed in JVM unit tests and
                // returns nothing, which would make this check silently unverifiable. minSdk 28
                // covers it, and IssueService already decodes this way.
                val json = String(Base64.getUrlDecoder().decode(payload))
                JSONObject(json).optJSONObject("cnf")?.optJSONObject("jwk")
            }.getOrNull() ?: return null
            val cnfThumbprint = runCatching {
                ECKey.parse(cnf.toString()).computeThumbprint().toString()
            }.getOrNull() ?: return null
            return thumbprint == cnfThumbprint
        }
}

/**
 * Whether the wallet makes the authorization request itself or hands a URL to a browser.
 *
 * Replaces `isApiCallRequired`, which did not say what it selected. RFC 8252: a scanned offer must
 * go through the browser so the authorization server's session cookie lands there -- interactive
 * servers depend on it. [InApp] is for first-party, non-interactive flows only, such as the
 * wallet-provider attestation bootstrap.
 */
enum class AuthorizationMode { Browser, InApp }

/**
 * Which credential is being asked for, when the caller wants to override what the session implies.
 *
 * Both are derived from the offer and the issuer configuration when null, using the existing
 * `getFormatFromIssuerConfig` and `getTypesFromCredentialOffer`.
 */
data class CredentialSelection(
    val format: String? = null,
    val docType: String? = null,
)
