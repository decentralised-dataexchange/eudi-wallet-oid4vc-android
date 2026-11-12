package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.protocol2

import com.nimbusds.jose.crypto.impl.ECDSA
import com.nimbusds.jose.jwk.ECKey
import java.security.MessageDigest
import java.security.Signature
import java.util.Base64

/**
 * The Content-Digest of a request body (RFC 9530): `sha-256=:<base64 of SHA-256 of the body>:`.
 * The base64 is the standard alphabet, with padding.
 */
object ContentDigest {
    fun sha256(body: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(body)
        return "sha-256=:" + Base64.getEncoder().encodeToString(digest) + ":"
    }
}

/**
 * The HTTP message signature of a protocol 2 request of the wallet provider (RFC 9421, label `wp`,
 * algorithm `ecdsa-p256-sha256`; CONTRACT.md section 2 of the wallet provider iteration 1).
 *
 * The signature base is RFC 9421 section 2.5: one line `"<component>": <value>` for each covered
 * component in the given order, then `"@signature-params": <params>`, LF line ends, no final LF.
 * The signature is the 64-byte r||s value of an ECDSA P-256 SHA-256 signature over the UTF-8 bytes
 * of the base, in standard base64 between colons.
 */
object HttpMessageSignature {

    const val LABEL = "wp"
    const val ALGORITHM = "ecdsa-p256-sha256"

    /** The result: the two header values, and the base (for diagnostics and tests only). */
    data class Signed(
        val signatureInput: String,
        val signature: String,
        val signatureBase: String
    )

    /** `("@method" "@target-uri" ...);created=<s>;keyid="<thumbprint>";alg="ecdsa-p256-sha256"` */
    fun signatureParams(components: List<String>, created: Long, keyId: String): String =
        components.joinToString(separator = " ", prefix = "(", postfix = ")") { "\"$it\"" } +
            ";created=$created;keyid=\"$keyId\";alg=\"$ALGORITHM\""

    /**
     * The signature base. [headers] has the header values; the lookup ignores the case of the
     * names. A value is trimmed (RFC 9421 section 2.1). A covered header that is not in
     * [headers] is an error.
     */
    fun signatureBase(
        method: String,
        targetUri: String,
        headers: Map<String, String>,
        components: List<String>,
        signatureParams: String
    ): String {
        val byName = headers.entries.associate { it.key.lowercase() to it.value }
        val lines = components.map { component ->
            val value = when (component) {
                "@method" -> method.uppercase()
                "@target-uri" -> targetUri
                else -> requireNotNull(byName[component]) { "the covered header $component is missing" }.trim()
            }
            "\"$component\": $value"
        }
        return (lines + "\"@signature-params\": $signatureParams").joinToString(separator = "\n")
    }

    /**
     * Signs the request. [signDer] gives the DER ECDSA P-256 SHA-256 signature of its input (for
     * example an Android Keystore key); the result has the raw r||s form of the contract.
     */
    fun sign(
        method: String,
        targetUri: String,
        headers: Map<String, String>,
        components: List<String>,
        created: Long,
        keyId: String,
        signDer: (ByteArray) -> ByteArray
    ): Signed {
        val params = signatureParams(components, created, keyId)
        val base = signatureBase(method, targetUri, headers, components, params)
        val raw = ECDSA.transcodeSignatureToConcat(signDer(base.toByteArray(Charsets.UTF_8)), 64)
        return Signed(
            signatureInput = "$LABEL=$params",
            signature = "$LABEL=:" + Base64.getEncoder().encodeToString(raw) + ":",
            signatureBase = base
        )
    }

    /** True when [rawSignatureBase64] (r||s, standard base64) verifies [signatureBase] with [publicKey]. */
    fun verify(signatureBase: String, rawSignatureBase64: String, publicKey: ECKey): Boolean = try {
        val der = ECDSA.transcodeSignatureToDER(Base64.getDecoder().decode(rawSignatureBase64))
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey.toECPublicKey())
            update(signatureBase.toByteArray(Charsets.UTF_8))
            verify(der)
        }
    } catch (e: Exception) {
        false
    }
}
