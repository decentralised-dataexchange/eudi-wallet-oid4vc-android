package com.ewc.eudi_wallet_oidc_android.services.verification.request

import com.ewc.eudi_wallet_oidc_android.services.verification.client.ClientIdentifierVerifier
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID

/**
 * OpenID4VP 1.0 section 5.10, Request URI Method `post`.
 *
 * When the authorization request carries `request_uri_method=post`, the request object is
 * fetched with an HTTP POST (`application/x-www-form-urlencoded`) that carries the wallet's
 * metadata and a fresh `wallet_nonce`. The verifier MUST echo that nonce in the signed request
 * object, and the wallet MUST refuse a request object that does not carry it back. Any other
 * value, or no value at all, keeps the plain GET of RFC 9101.
 */
internal object RequestUriMethod {

    const val PARAM = "request_uri_method"
    const val WALLET_NONCE = "wallet_nonce"
    const val WALLET_METADATA = "wallet_metadata"
    const val REQUEST_OBJECT_MEDIA_TYPE = "application/oauth-authz-req+jwt"

    /** True when the authorization request asks for the request object to be fetched by POST. */
    fun isPost(authorisationRequestData: String): Boolean =
        queryParameter(authorisationRequestData, PARAM)?.trim().equals("post", ignoreCase = true)

    /** The `request_uri` of the authorization request, or null when it carries none. */
    fun requestUri(authorisationRequestData: String): String? =
        queryParameter(authorisationRequestData, "request_uri")?.takeIf { it.isNotBlank() }

    /** Reads one query parameter from the raw authorization request URI. */
    internal fun queryParameter(uri: String, name: String): String? =
        AuthorizationRequestUri.queryParam(uri, name)

    /** A fresh, URL-safe random value for the `wallet_nonce` POST parameter. */
    fun newWalletNonce(): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    /**
     * A fresh P-256 key for one request-object fetch. Section 5.10: "If the Wallet requires the
     * Verifier to encrypt the Request Object, it SHOULD use the `jwks` parameter within the
     * `wallet_metadata` parameter to pass public encryption keys." The private half never leaves
     * the fetch that created it.
     */
    fun newEncryptionKey(): ECKey =
        ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.ENCRYPTION)
            .algorithm(JWEAlgorithm.ECDH_ES)
            .keyID(UUID.randomUUID().toString())
            .generate()

    /**
     * Unwraps an encrypted request object (RFC 9101 section 6.1, a JWE whose payload is the signed
     * request JWT) with [key]. A body that is not a JWE is returned untouched, so a verifier that
     * chose not to encrypt still works. Null when the body is a JWE this key cannot open.
     */
    fun unwrapEncrypted(body: String, key: ECKey): String? {
        val trimmed = body.trim()
        if (trimmed.count { it == '.' } != 4) return trimmed
        return try {
            JWEObject.parse(trimmed).apply { decrypt(ECDHDecrypter(key)) }.payload.toString()
        } catch (e: Exception) {
            null
        }
    }

    /**
     * The wallet metadata sent with the POST (OpenID4VP 1.0 section 10 and 5.10): the credential
     * formats and algorithms this SDK can present, the client id prefixes it can verify, the
     * response modes it can answer with, and, when [encryptionKey] is given, the public key and
     * algorithms the verifier can use to encrypt the request object. Serialised as the JSON string
     * the form parameter expects.
     */
    fun walletMetadata(
        encryptionKey: ECKey? = null,
        clientIdPrefixes: List<String> = ClientIdentifierVerifier().supportedPrefixes(PresentationRequestPolicy.Default),
    ): String {
        val es256 = JsonArray().apply { add("ES256") }
        val coseEs256 = JsonArray().apply { add(-7) }
        val formats = JsonObject().apply {
            add("dc+sd-jwt", JsonObject().apply {
                add("sd-jwt_alg_values", es256)
                add("kb-jwt_alg_values", es256)
            })
            add("mso_mdoc", JsonObject().apply {
                add("issuerauth_alg_values", coseEs256)
                add("deviceauth_alg_values", coseEs256)
            })
        }
        // Derived from the client identifier registry, so the advertisement and the enforcement
        // cannot drift apart.
        val prefixes = JsonArray().apply { clientIdPrefixes.forEach { add(it) } }
        val responseModes = JsonArray().apply {
            listOf("direct_post", "direct_post.jwt").forEach { add(it) }
        }
        return JsonObject().apply {
            add("vp_formats_supported", formats)
            add("client_id_prefixes_supported", prefixes)
            add("response_modes_supported", responseModes)
            add("request_object_signing_alg_values_supported", es256)
            if (encryptionKey != null) {
                val keys = JsonArray().apply {
                    add(JsonParser.parseString(encryptionKey.toPublicJWK().toJSONString()))
                }
                add("jwks", JsonObject().apply { add("keys", keys) })
                add("request_object_encryption_alg_values_supported", JsonArray().apply {
                    listOf(JWEAlgorithm.ECDH_ES, JWEAlgorithm.ECDH_ES_A128KW, JWEAlgorithm.ECDH_ES_A256KW)
                        .forEach { add(it.name) }
                })
                add("request_object_encryption_enc_values_supported", JsonArray().apply {
                    listOf(EncryptionMethod.A128GCM, EncryptionMethod.A256GCM, EncryptionMethod.A128CBC_HS256)
                        .forEach { add(it.name) }
                })
            }
        }.toString()
    }

    /**
     * Section 5.10: if the wallet sent a `wallet_nonce`, the request object MUST carry the same
     * value back. [sent] is null when the request object was fetched by GET, and then nothing is
     * checked.
     */
    fun nonceAccepted(sent: String?, received: String?): Boolean =
        sent == null || (received != null && received == sent)
}
