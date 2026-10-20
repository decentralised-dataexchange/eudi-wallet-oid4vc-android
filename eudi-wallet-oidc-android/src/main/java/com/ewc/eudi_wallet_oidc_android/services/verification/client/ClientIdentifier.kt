package com.ewc.eudi_wallet_oidc_android.services.verification.client

/**
 * A `client_id` split into its prefix and the identifier the prefix gives meaning to.
 *
 * Section 5.9.1: "Wallets MUST use the presence of a : (colon) character and the content
 * preceding it to determine whether a Client Identifier Prefix is used." Section 5.9.2: without a
 * colon, or with an unrecognised prefix, the client is pre-registered.
 */
data class ClientIdentifier(
    val prefix: ClientIdPrefix,
    /** The part the prefix applies to. For legacy and pre-registered clients, the whole client id. */
    val identifier: String,
    /** The `client_id` exactly as received; the audience of the presentation. */
    val original: String,
    /** Set when the client id carried a prefix this SDK does not know. */
    val unrecognisedPrefix: String? = null,
) {
    companion object {

        /**
         * @param legacyScheme the draft 20 `client_id_scheme` parameter, which named the scheme
         *   outside the client id. Honoured only when the client id itself carries no 1.0 prefix.
         */
        fun parse(clientId: String, legacyScheme: String? = null): ClientIdentifier {
            val head = clientId.substringBefore(':', missingDelimiterValue = "")
            val fromHead = ClientIdPrefix.fromValue(head.takeIf { it.isNotEmpty() })

            if (fromHead != null && !fromHead.legacy) {
                return ClientIdentifier(fromHead, clientId.substringAfter(':'), clientId)
            }
            ClientIdPrefix.fromValue(legacyScheme?.trim()?.takeIf { it.isNotEmpty() })?.let { scheme ->
                return ClientIdentifier(scheme, clientId, clientId)
            }
            if (fromHead != null) {
                // https://..., did:..., web-origin:... keep the whole value as the identifier.
                return ClientIdentifier(fromHead, clientId, clientId)
            }
            return ClientIdentifier(
                prefix = ClientIdPrefix.PRE_REGISTERED,
                identifier = clientId,
                original = clientId,
                unrecognisedPrefix = head.takeIf { clientId.contains(':') && it.isNotEmpty() },
            )
        }
    }
}
