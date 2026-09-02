package com.ewc.eudi_wallet_oidc_android.services.discovery.metadata

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration

/** Where the chosen authorization server came from. */
enum class AuthorizationServerSource {
    /** The draft-era singular `authorization_server` parameter. */
    SingularParameter,

    /** The only entry in `authorization_servers`. */
    SoleEntry,

    /** The entry in `authorization_servers` the credential offer pointed at. */
    OfferHint,

    /** The first of several entries, with no hint to narrow them. */
    FirstOfSeveral,

    /**
     * `authorization_servers` was absent and the metadata carried a draft-era `issuer`.
     *
     * Not an OpenID4VCI parameter -- it is the RFC 8414 / OpenID Connect Discovery identifier,
     * which issuers acting as their own authorization server sometimes publish alongside their
     * Credential Issuer Identifier. Preferred over the Credential Issuer Identifier only because
     * that is what hosts implementing this themselves have always done.
     */
    IssuerParameter,

    /**
     * `authorization_servers` was absent, so the Credential Issuer is its own authorization
     * server (OpenID4VCI 1.0 section 12.2.4).
     */
    CredentialIssuer,
}

/** The chosen authorization server, and how it was chosen. */
data class AuthorizationServerSelection(
    val identifier: String,
    val source: AuthorizationServerSource,
    /** Every candidate that was available, in declaration order. */
    val candidates: List<String>,
)

/**
 * Picks which authorization server to talk to, per OpenID4VCI 1.0 section 12.2.4.
 *
 * This used to live in the wallet, where two of the spec's rules were not implemented: an absent
 * `authorization_servers` dead-ended instead of falling back to the Credential Issuer, and a
 * credential offer naming an authorization server that is not in the array silently fell through
 * to the first entry, which the spec forbids outright.
 */
class AuthorizationServerSelector {

    /**
     * @param hint the credential offer's `authorization_server` grant parameter, if any.
     * @throws DiscoveryException.Invalid when the spec says the flow must not proceed.
     */
    fun select(
        issuerConfig: IssuerWellKnownConfiguration?,
        hint: String? = null,
    ): AuthorizationServerSelection {
        val credentialIssuer = issuerConfig?.credentialIssuer?.trim()

        // Draft-era singular parameter. Still first, because it is what every pre-1.0 issuer
        // publishes -- the EBSI conformance issuer among them -- and 1.0 issuers do not send it.
        val singular = issuerConfig?.authorizationServer?.trim()
        if (!singular.isNullOrEmpty()) {
            if (!hint.isNullOrBlank() && hint != singular) {
                Logger.d(TAG, "Ignoring the offer's authorization_server: this issuer declares a single authorization_server")
            }
            return AuthorizationServerSelection(singular, AuthorizationServerSource.SingularParameter, listOf(singular))
        }

        val servers = issuerConfig?.authorizationServers?.map { it.trim() }?.filter { it.isNotEmpty() }.orEmpty()

        if (servers.isEmpty()) {
            // "If this parameter is omitted, the entity providing the Credential Issuer is also
            // acting as the Authorization Server, i.e., the Credential Issuer's identifier is used
            // to obtain the Authorization Server metadata."
            // A draft-era `issuer` comes first, matching what hosts have always done here; the
            // spec's rule -- the Credential Issuer is its own authorization server -- is the
            // fallback, and is what 1.0 metadata reaches.
            val declaredIssuer = issuerConfig?.issuer?.trim()
            if (!declaredIssuer.isNullOrEmpty()) {
                return AuthorizationServerSelection(
                    declaredIssuer,
                    AuthorizationServerSource.IssuerParameter,
                    listOf(declaredIssuer),
                )
            }

            if (credentialIssuer.isNullOrEmpty()) {
                throw DiscoveryException.Invalid(
                    "The issuer configuration names no authorization server"
                )
            }
            return AuthorizationServerSelection(
                credentialIssuer,
                AuthorizationServerSource.CredentialIssuer,
                listOf(credentialIssuer),
            )
        }

        if (hint.isNullOrBlank()) {
            val source = if (servers.size == 1) {
                AuthorizationServerSource.SoleEntry
            } else {
                // The spec suggests narrowing by querying each server's metadata, for example by
                // grant_types_supported. That belongs to the authorization step, which knows which
                // grant it intends to use; until then the first entry is taken and said out loud.
                Logger.d(TAG, "Issuer declares ${servers.size} authorization servers and the offer named none; using the first")
                AuthorizationServerSource.FirstOfSeveral
            }
            return AuthorizationServerSelection(servers.first(), source, servers)
        }

        // "The Wallet MUST NOT proceed with the flow if the authorization_server Credential Offer
        // parameter value does not match any of the entries in the authorization_servers array."
        val matched = servers.firstOrNull { it == hint }
            ?: throw DiscoveryException.Invalid(
                "The credential offer names an authorization server the issuer does not list ($hint)"
            )

        if (servers.size == 1) {
            // "It MUST NOT be used otherwise" -- the hint is only meaningful with multiple entries.
            // It matches, so nothing is at stake; note it and carry on.
            Logger.d(TAG, "The offer named an authorization_server though the issuer declares only one")
            return AuthorizationServerSelection(matched, AuthorizationServerSource.SoleEntry, servers)
        }
        return AuthorizationServerSelection(matched, AuthorizationServerSource.OfferHint, servers)
    }

    /**
     * The `authorization_server` hint carried by [offer].
     *
     * The field is modelled as `Any?` because issuers have been seen sending both a string and a
     * single-element array. The authorization-code grant is checked first, then the pre-authorized
     * grant.
     */
    fun hintFrom(offer: CredentialOffer?): String? {
        val fromAuthCode = asIdentifier(offer?.grants?.authorizationCode?.authorizationServer)
        if (!fromAuthCode.isNullOrBlank()) return fromAuthCode
        return asIdentifier(offer?.grants?.preAuthorizationCode?.authorizationServer)
    }

    private fun asIdentifier(value: Any?): String? = when (value) {
        is String -> value.trim().takeIf { it.isNotEmpty() }
        is List<*> -> value.filterIsInstance<String>().firstOrNull()?.trim()?.takeIf { it.isNotEmpty() }
        else -> null
    }

    private companion object {
        const val TAG = "AuthorizationServerSelector"
    }
}
