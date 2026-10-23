package com.ewc.eudi_wallet_oidc_android.services.verification.match

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.TrustedAuthority
import com.ewc.eudi_wallet_oidc_android.services.utils.filterByTrustedAuthorities
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * OpenID4VP 1.0 section 6.1.1: "A Credential is identified as a match to a Trusted Authorities
 * Query if it matches with one of the provided values in one of the provided types."
 */
internal object TrustedAuthorityMatcher {

    private const val TAG = "TrustedAuthorityMatcher"
    private const val AUTHORITY_KEY_IDENTIFIER_OID = "2.5.29.35"

    suspend fun matches(candidate: CandidateCredential, authorities: List<TrustedAuthority>): Boolean =
        authorities.any { authority ->
            when (authority.type) {
                // 6.1.1.1: the KeyIdentifier of the AuthorityKeyIdentifier, base64url, of any
                // certificate in the credential's chain.
                "aki" -> {
                    val wanted = authority.values.orEmpty().toSet()
                    candidate.certificates.any { cert -> authorityKeyIdentifier(cert)?.let { it in wanted } == true }
                }
                // 6.1.1.2: an entry of the referenced ETSI trusted list. The existing trust list
                // lookup resolves the list and compares the chain.
                "etsi_tl" -> filterByTrustedAuthorities(listOf(candidate.raw), listOf(authority), isDCQLVerificationFlow = true).isNotEmpty()
                else -> {
                    Logger.w(TAG, "trusted_authorities type '${authority.type}' is not supported; the entry matches nothing")
                    false
                }
            }
        }

    /** The KeyIdentifier inside the AuthorityKeyIdentifier extension (RFC 5280 section 4.2.1.1), base64url without padding. */
    fun authorityKeyIdentifier(cert: X509Certificate): String? {
        val extension = cert.getExtensionValue(AUTHORITY_KEY_IDENTIFIER_OID) ?: return null
        // The extension value is an OCTET STRING wrapping SEQUENCE { [0] keyIdentifier, ... }.
        val sequence = derContent(extension, 0x04) ?: return null
        val seqContent = derContent(sequence, 0x30) ?: return null
        if (seqContent.isEmpty() || seqContent[0].toInt() and 0xFF != 0x80) return null
        val keyId = derContent(seqContent, 0x80) ?: return null
        return Base64.getUrlEncoder().withoutPadding().encodeToString(keyId)
    }

    /** The content octets of the first DER TLV in [bytes] when its tag is [tag]. */
    private fun derContent(bytes: ByteArray, tag: Int): ByteArray? {
        if (bytes.size < 2 || bytes[0].toInt() and 0xFF != tag) return null
        var length = bytes[1].toInt() and 0xFF
        var offset = 2
        if (length and 0x80 != 0) {
            val count = length and 0x7F
            if (count == 0 || count > 4 || bytes.size < 2 + count) return null
            length = 0
            repeat(count) { length = (length shl 8) or (bytes[2 + it].toInt() and 0xFF) }
            offset = 2 + count
        }
        if (bytes.size < offset + length) return null
        return bytes.copyOfRange(offset, offset + length)
    }
}
