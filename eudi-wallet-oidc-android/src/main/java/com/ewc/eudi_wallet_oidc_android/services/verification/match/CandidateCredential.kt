package com.ewc.eudi_wallet_oidc_android.services.verification.match

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import com.ewc.eudi_wallet_oidc_android.services.utils.CborUtils
import com.ewc.eudi_wallet_oidc_android.services.utils.CredentialProcessor
import com.google.gson.JsonElement
import com.google.gson.JsonParser
import com.nimbusds.jwt.JWTParser
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * One stored credential decoded once for matching, whatever its format, so the matcher never
 * keeps parallel lists aligned by index.
 */
internal class CandidateCredential private constructor(
    val raw: String,
    val format: Format,
    /** The claims as JSON: the SD-JWT payload with disclosures applied, the `vc` object of a JWT VC, or the mdoc namespaces. */
    val json: JsonElement,
    val docType: String?,
    /** Section 6.1 `require_cryptographic_holder_binding`: an SD-JWT with `cnf`, or an mdoc with a device key. */
    val holderBound: Boolean,
    /** The issuer's certificate chain when the credential carries one (`x5c` header or `x5chain`). */
    val certificates: List<X509Certificate>,
) {
    enum class Format { SD_JWT, JWT_VC, MDOC }

    fun accepts(formatIdentifier: String?): Boolean = when (format) {
        Format.SD_JWT -> formatIdentifier == "dc+sd-jwt" || formatIdentifier == "vc+sd-jwt"
        Format.JWT_VC -> formatIdentifier == "jwt_vc_json" || formatIdentifier == "jwt_vc"
        Format.MDOC -> formatIdentifier == "mso_mdoc"
    }

    companion object {

        fun decode(raw: String?): CandidateCredential? {
            if (raw.isNullOrBlank()) return null
            return try {
                if (raw.contains('.')) decodeJwt(raw) else decodeMdoc(raw)
            } catch (e: Exception) {
                null
            }
        }

        private fun decodeJwt(raw: String): CandidateCredential? {
            val issuerJwt = raw.substringBefore('~')
            val parsed = JWTParser.parse(issuerJwt)
            val payload = parsed.jwtClaimsSet
            val jsonText = CredentialProcessor.processCredentialsToJsonString(arrayListOf(raw)).firstOrNull() ?: return null
            val json = JsonParser.parseString(jsonText)
            val isSdJwt = raw.contains('~') || payload.getClaim("vct") != null
            val chain = (parsed.header as? com.nimbusds.jose.JWSHeader)?.x509CertChain?.mapNotNull { encoded ->
                try {
                    CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(encoded.decode())) as X509Certificate
                } catch (e: Exception) {
                    null
                }
            }.orEmpty()
            return CandidateCredential(
                raw = raw,
                format = if (isSdJwt) Format.SD_JWT else Format.JWT_VC,
                json = json,
                docType = null,
                holderBound = payload.getClaim("cnf") != null,
                certificates = chain,
            )
        }

        private fun decodeMdoc(raw: String): CandidateCredential? {
            val jsonText = CborUtils.processMdocCredentialToJsonString(listOf(raw))?.firstOrNull() ?: return null
            return CandidateCredential(
                raw = raw,
                format = Format.MDOC,
                json = JsonParser.parseString(jsonText),
                docType = CborUtils.extractDocTypeFromIssuerAuth(listOf(raw)),
                holderBound = CborUtils.extractDeviceKeyFromIssuerSigned(raw) != null,
                certificates = mdocChain(raw),
            )
        }

        /** The COSE `x5chain` (label 33) of the issuerAuth unprotected header. */
        private fun mdocChain(raw: String): List<X509Certificate> = try {
            val padded = raw + "=".repeat((4 - raw.length % 4) % 4)
            val signed = CborDecoder(ByteArrayInputStream(Base64.getUrlDecoder().decode(padded))).decode().first() as CborMap
            val issuerAuth = signed[UnicodeString("issuerAuth")] as CborArray
            val unprotected = issuerAuth.dataItems[1] as CborMap
            val value = unprotected[UnsignedInteger(33)]
            val items = when (value) {
                is CborArray -> value.dataItems
                is ByteString -> listOf(value)
                else -> emptyList()
            }
            val factory = CertificateFactory.getInstance("X.509")
            items.mapNotNull { (it as? ByteString)?.bytes }
                .map { factory.generateCertificate(ByteArrayInputStream(it)) as X509Certificate }
        } catch (e: Exception) {
            emptyList()
        }
    }
}
