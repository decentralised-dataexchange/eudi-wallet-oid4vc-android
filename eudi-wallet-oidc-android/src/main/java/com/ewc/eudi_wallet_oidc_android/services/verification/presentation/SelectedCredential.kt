package com.ewc.eudi_wallet_oidc_android.services.verification.presentation

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.nimbusds.jose.jwk.JWK
import com.ewc.eudi_wallet_oidc_android.services.verification.transaction.TransactionDataHashes

/**
 * What the user picked for one query entry, with the key that binds the credential to this
 * wallet. [key] is null when the credential has no key of its own; the holder identity's key is
 * used then.
 *
 * @param entryId the [com.ewc.eudi_wallet_oidc_android.services.verification.match.QueryEntry] id
 *   this credential answers: the DCQL credential query id or the input descriptor id.
 * @param credential the credential as it should be presented: an SD-JWT with the chosen
 *   disclosures and a trailing `~`, a JWT VC, or an mdoc IssuerSigned with the chosen elements.
 */
data class SelectedCredential(
    val entryId: String,
    val credential: String,
    val key: JWK? = null,
)

/**
 * The authentication factors a strong customer authentication flow reports in the key binding
 * JWT's `amr`, beside the possession factor the key itself proves.
 */
data class AuthenticationMethods(
    val inherence: String? = null,
    val knowledge: String? = null,
) {
    fun amr(): List<Map<String, String>> = buildList {
        add(mapOf("possession" to "key_in_local_native_wscd"))
        inherence?.let { add(mapOf("inherence" to it)) }
        knowledge?.let { add(mapOf("knowledge" to it)) }
    }
}

/** The credential format identifiers a presentation can take. */
enum class PresentationFormat(val identifier: String) {
    SD_JWT("dc+sd-jwt"),
    MDOC("mso_mdoc"),
    W3C_VP("jwt_vp"),
}

/**
 * One element of the `vp_token`.
 *
 * @param entryIds the query entries this element answers: one id, or one per credential inside
 *   an aggregated W3C presentation, in the order the credentials appear in it.
 * @param token the presentation: SD-JWT+KB, a base64url DeviceResponse, or a signed W3C VP JWT.
 */
data class Presentation(
    val entryIds: List<String>,
    val format: PresentationFormat,
    val token: String,
) {
    val entryId: String get() = entryIds.first()
}

/**
 * Everything the format builders share for one response.
 *
 * @param holder the wallet's identity; its key signs whatever has no key of its own.
 * @param transactionDataHashes per query entry id, the base64url hashes of the `transaction_data`
 *   entries that name it, for the key binding JWT. Computed by the caller.
 * @param strongCustomerAuthentication true for a TS12 SCA flow: the key binding JWT then carries
 *   `response_mode` and `amr`.
 * @param encryptionKeyThumbprint RFC 7638 thumbprint of the verifier's encryption key, for the
 *   mdoc session transcript when the response is encrypted. Null when it is not.
 */
data class PresentationInputs(
    val request: PresentationRequest,
    val holder: WalletIdentity?,
    val transactionDataHashes: Map<String, TransactionDataHashes> = emptyMap(),
    val strongCustomerAuthentication: Boolean = false,
    val authentication: AuthenticationMethods? = null,
    val encryptionKeyThumbprint: ByteArray? = null,
)
