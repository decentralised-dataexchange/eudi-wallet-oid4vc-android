package com.ewc.eudi_wallet_oidc_android.services.discovery.metadata

/**
 * Which revision of the OpenID4VCI Credential Issuer metadata an issuer published.
 *
 * [V1_0] is the target and is always tried first. [Draft] exists only to keep pre-1.0 issuers
 * working and is quarantined in the `legacy` package so it can be removed as a block.
 *
 * Deliberately separate from
 * [com.ewc.eudi_wallet_oidc_android.services.issue.offer.CredentialOfferSpecVersion]: that enum
 * carries a `legacyVersionCode` that only means something for a credential offer. If a third
 * consumer appears, merge the two into one shared enum rather than adding a second shim here.
 */
enum class IssuerMetadataSpecVersion {
    /** OpenID4VCI 1.0: `credential_configurations_supported`, `authorization_servers`. */
    V1_0,

    /** Pre-1.0 drafts: `credentials_supported`, singular `authorization_server`. */
    Draft,
}
