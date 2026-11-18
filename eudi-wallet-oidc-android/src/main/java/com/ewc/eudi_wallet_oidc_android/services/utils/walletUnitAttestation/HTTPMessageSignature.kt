package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation

import java.security.MessageDigest
import java.util.Base64

/**
 * The HTTP message signature of a wallet provider protocol 2 request: RFC 9421
 * with the label `wp` and the algorithm `ecdsa-p256-sha256`, over a body bound
 * by an RFC 9530 Content-Digest.
 *
 * Pure functions that build the `Content-Digest`, `Signature-Input` and
 * `Signature` headers. The wallet provider rebuilds the signature base from
 * the request it receives and verifies it with the device key of the wallet
 * unit, so every byte here is wire contract: the order of the components, the
 * quoting, the LF line ends.
 */
internal object HTTPMessageSignature {

    const val LABEL = "wp"
    const val ALGORITHM = "ecdsa-p256-sha256"

    /**
     * `sha-256=:<standard base64 with padding of SHA-256(body)>:` (RFC 9530).
     * The body must be the exact bytes that go on the wire.
     */
    fun contentDigest(body: ByteArray): String =
        "sha-256=:" + Base64.getEncoder().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(body)
        ) + ":"

    /**
     * The signature parameters, the text after `wp=` in `Signature-Input`:
     *
     *     ("@method" "@target-uri" ...);created=<s>;keyid="<thumbprint>";alg="ecdsa-p256-sha256"
     */
    fun signatureParams(components: List<String>, created: Long, keyId: String): String =
        components.joinToString(separator = " ", prefix = "(", postfix = ")") { "\"$it\"" } +
            ";created=$created;keyid=\"$keyId\";alg=\"$ALGORITHM\""

    /**
     * The signature base (RFC 9421 section 2.5): one line `"<component>": <value>`
     * for each covered component, in order, then the `"@signature-params"` line.
     * LF line ends, no LF at the end.
     *
     * `@method` and `@target-uri` come from the arguments; every other
     * component is a header of [headers], looked up without regard to case and
     * trimmed (RFC 9421 section 2.1). Null when a covered header is missing:
     * such a request cannot be signed.
     */
    fun signatureBase(
        method: String,
        targetUri: String,
        headers: Map<String, String>,
        components: List<String>,
        signatureParams: String
    ): String? {
        val byName = headers.entries
            .groupBy({ it.key.lowercase() }, { it.value })
            .mapValues { it.value.first() }
        val lines = components.map { component ->
            val value = when (component) {
                "@method" -> method.uppercase()
                "@target-uri" -> targetUri
                else -> byName[component]?.trim() ?: return null
            }
            "\"$component\": $value"
        }
        return (lines + "\"@signature-params\": $signatureParams").joinToString(separator = "\n")
    }

    /** The signed headers of a request. */
    class Signed(
        val signatureInput: String,
        val signature: String,
        /** For tests and diagnostics only; never log it in a release build. */
        val signatureBase: String
    )

    /**
     * Signs a request with [key]. [headers] must already hold every covered
     * header with the value that goes on the wire. Null when a covered header
     * is missing; throws when the key refuses to sign.
     */
    fun sign(
        method: String,
        targetUri: String,
        headers: Map<String, String>,
        components: List<String>,
        created: Long,
        key: RequestSigningKey
    ): Signed? {
        val params = signatureParams(components, created, key.keyId)
        val base = signatureBase(method, targetUri, headers, components, params) ?: return null
        val raw = key.signRaw(base.toByteArray(Charsets.UTF_8))
        return Signed(
            signatureInput = "$LABEL=$params",
            signature = "$LABEL=:${Base64.getEncoder().encodeToString(raw)}:",
            signatureBase = base
        )
    }
}
