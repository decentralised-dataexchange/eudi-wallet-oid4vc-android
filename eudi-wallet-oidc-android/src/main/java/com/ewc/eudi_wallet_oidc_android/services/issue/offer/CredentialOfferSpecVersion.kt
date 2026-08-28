package com.ewc.eudi_wallet_oidc_android.services.issue.offer

/**
 * Which revision of the OpenID4VCI Credential Offer an issuer sent.
 *
 * [V1_0] is the target: new work is built around it, and it is always tried first. [Draft] exists
 * only to keep pre-1.0 issuers working and is quarantined in the `legacy` packages so it can be
 * removed as a block.
 */
enum class CredentialOfferSpecVersion(
    /**
     * The value written to [com.ewc.eudi_wallet_oidc_android.models.CredentialOffer.version].
     *
     * Compatibility shim. The wallet keys `user_pin` vs `tx_code` and first-vs-last `types`
     * selection off this Int, so it cannot change; this enum is the internal truth.
     */
    internal val legacyVersionCode: Int
) {
    /** OpenID4VCI 1.0: `credential_configuration_ids`, `tx_code`. */
    V1_0(2),

    /** Pre-1.0 drafts: `credentials`, `user_pin_required`. */
    Draft(1),
}
