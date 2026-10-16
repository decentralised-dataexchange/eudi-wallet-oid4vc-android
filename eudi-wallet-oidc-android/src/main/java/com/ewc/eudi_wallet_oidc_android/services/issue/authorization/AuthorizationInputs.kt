package com.ewc.eudi_wallet_oidc_android.services.issue.authorization

import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
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
     * Whether this issuer is positively identified as a pre-1.0 draft.
     *
     * The one answer that decides both how the credential request names the credential and which
     * proof form it sends, so a request can never mix shapes from two revisions. 1.0 is the
     * default: the absence of a 1.0 feature proves nothing, since a 1.0 issuer that needs no
     * `c_nonce` publishes no nonce endpoint (section 12.2.4) and one that requires no key binding
     * declares no `proof_types_supported`. Any one of these markers is enough:
     *
     *  - the offer had a draft shape (EBSI, EWC), recorded by the offer parser as version 1;
     *  - the metadata had the draft `credentials_supported` shape, recorded by discovery as
     *    version 1, or as an array for a configuration stored before that field existed;
     *  - the token response carried `c_nonce` and the issuer publishes no nonce endpoint. 1.0
     *    moved `c_nonce` out of the token response, so this is how drafts 13 and 14 hand it out.
     *
     * A draft 13 or 14 issuer that returns no `c_nonce` shows none of these and is treated as
     * 1.0. Stepping such an issuer back by hand takes both a `CredentialSubject.LegacyFormat` for
     * the name and `CredentialRequestPolicy.Legacy` for the proof form.
     */
    fun isDraftIssuer(token: TokenResponse?): Boolean =
        offerVersion == DRAFT_VERSION ||
            issuerConfig?.version == DRAFT_VERSION ||
            issuerConfig?.credentialsSupported is List<*> ||
            (issuerConfig?.nonceEndpoint.isNullOrBlank() && !token?.cNonce.isNullOrBlank())

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

    private companion object {
        /** The code the offer and metadata parsers record for a pre-1.0 draft shape. */
        const val DRAFT_VERSION = 1
    }
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
