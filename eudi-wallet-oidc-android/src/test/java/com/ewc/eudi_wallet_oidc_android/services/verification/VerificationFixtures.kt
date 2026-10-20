package com.ewc.eudi_wallet_oidc_android.services.verification

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import com.ewc.eudi_wallet_oidc_android.models.CredentialList
import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.ewc.eudi_wallet_oidc_android.models.InputDescriptors
import com.ewc.eudi_wallet_oidc_android.models.Jwt
import com.ewc.eudi_wallet_oidc_android.models.Meta
import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.deviceSigned.buildProtectedHeader
import com.google.gson.JsonElement
import com.google.gson.JsonParser
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Base64

/**
 * Shared inputs for the verification characterisation tests: a holder key, the three credential
 * shapes the builders accept, and the two request shapes (Presentation Exchange and DCQL).
 */
internal object VerificationFixtures {

    const val CLIENT_ID = "x509_san_dns:verifier.example.com"
    const val NONCE = "n-verifier-1"
    const val STATE = "s-1"
    const val RESPONSE_URI = "https://verifier.example.com/response"
    const val DID = "did:key:zTestHolder"
    const val VCT = "urn:eudi:pid:1"
    const val DOC_TYPE = "org.iso.18013.5.1.mDL"

    private val issuerKey: ECKey = ECKeyGenerator(Curve.P_256).keyID("issuer").generate()

    fun key(kid: String = "holder"): ECKey = ECKeyGenerator(Curve.P_256).keyID(kid).generate()

    fun signedJwt(claims: Map<String, Any?>): String {
        val builder = JWTClaimsSet.Builder()
        claims.forEach { (k, v) -> builder.claim(k, v) }
        return SignedJWT(JWSHeader.Builder(JWSAlgorithm.ES256).keyID("issuer").build(), builder.build())
            .apply { sign(ECDSASigner(issuerKey)) }
            .serialize()
    }

    /** An SD-JWT with no disclosures: issuer JWT followed by the `~` separator. */
    fun sdJwt(vct: String = VCT): String =
        signedJwt(mapOf("vct" to vct, "iss" to "https://issuer.example", "given_name" to "Alice")) + "~"

    /** A W3C VC as a plain JWT, no `vct`. */
    fun jwtVc(): String = signedJwt(
        mapOf("iss" to "https://issuer.example", "vc" to mapOf("type" to listOf("VerifiableCredential")))
    )

    private fun encode(item: DataItem): ByteArray =
        ByteArrayOutputStream().also { CborEncoder(it).encode(item) }.toByteArray()

    /** A minimal IssuerSigned (empty name spaces) whose MSO names [docType] and binds [deviceKey]. */
    fun mdoc(
        deviceKey: ECKey?,
        docType: String = DOC_TYPE,
        nameSpaces: Map<String, Map<String, Any>> = emptyMap(),
    ): String {
        val mso = CborMap().apply {
            put(UnicodeString("docType"), UnicodeString(docType))
            if (deviceKey != null) {
                val coseKey = CborMap().apply {
                    put(UnsignedInteger(1), UnsignedInteger(2))
                    put(NegativeInteger(-1), UnsignedInteger(1))
                    put(NegativeInteger(-2), ByteString(deviceKey.x.decode()))
                    put(NegativeInteger(-3), ByteString(deviceKey.y.decode()))
                }
                put(UnicodeString("deviceKeyInfo"), CborMap().apply { put(UnicodeString("deviceKey"), coseKey) })
            }
        }
        val taggedMso = ByteString(encode(mso)).apply { setTag(24) }
        val issuerAuth = CborArray().apply {
            add(ByteString(buildProtectedHeader()))
            add(CborMap())
            add(ByteString(encode(taggedMso)))
            add(ByteString(ByteArray(64)))
        }
        val issuerNameSpaces = CborMap().apply {
            nameSpaces.forEach { (namespace, elements) ->
                val items = CborArray()
                elements.entries.forEachIndexed { index, (identifier, value) ->
                    val item = CborMap().apply {
                        put(UnicodeString("digestID"), UnsignedInteger(index.toLong()))
                        put(UnicodeString("random"), ByteString(ByteArray(16) { index.toByte() }))
                        put(UnicodeString("elementIdentifier"), UnicodeString(identifier))
                        put(UnicodeString("elementValue"), when (value) {
                            is Int -> UnsignedInteger(value.toLong())
                            is Long -> UnsignedInteger(value)
                            else -> UnicodeString(value.toString())
                        })
                    }
                    items.add(ByteString(encode(item)).apply { setTag(24) })
                }
                put(UnicodeString(namespace), items)
            }
        }
        val signed = CborMap().apply {
            put(UnicodeString("nameSpaces"), issuerNameSpaces)
            put(UnicodeString("issuerAuth"), issuerAuth)
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(encode(signed))
    }

    fun decodeCbor(base64Url: String): DataItem =
        CborDecoder(ByteArrayInputStream(Base64.getUrlDecoder().decode(base64Url))).decode().first()

    // --- Presentation Exchange ---

    fun sdJwtDescriptor(id: String = "pid") =
        InputDescriptors(id = id, format = mapOf("vc+sd-jwt" to Jwt(arrayListOf("ES256"))))

    fun jwtDescriptor(id: String = "vc") =
        InputDescriptors(id = id, format = mapOf("jwt_vp" to Jwt(arrayListOf("ES256"))))

    fun mdocDescriptor(id: String = "mdl") =
        InputDescriptors(id = id, format = mapOf("mso_mdoc" to Jwt(arrayListOf("ES256"))))

    fun pexRequest(
        vararg descriptors: InputDescriptors,
        responseType: String? = "vp_token",
        responseMode: String = "direct_post",
        transactionData: List<String>? = null,
        clientMetadata: Any? = null,
    ) = PresentationRequest(
        clientId = CLIENT_ID,
        nonce = NONCE,
        state = STATE,
        responseType = responseType,
        responseMode = responseMode,
        responseUri = RESPONSE_URI,
        presentationDefinition = PresentationDefinition(id = "pd-1", inputDescriptors = arrayListOf(*descriptors)),
        transactionDdata = transactionData?.let { ArrayList(it) },
        clientMetaDetails = clientMetadata,
    )

    // --- DCQL ---

    fun dcqlSdJwt(id: String = "pid", vct: String = VCT) =
        CredentialList(id = id, format = "dc+sd-jwt", meta = Meta(vctValues = arrayListOf(vct)))

    fun dcqlMdoc(id: String = "mdl", docType: String = DOC_TYPE) =
        CredentialList(id = id, format = "mso_mdoc", meta = Meta(doctypeValue = docType))

    fun dcqlJwt(id: String = "vc") =
        CredentialList(id = id, format = "jwt_vc_json", meta = Meta(typeValues = listOf(listOf("VerifiableCredential"))))

    fun dcqlRequest(
        vararg entries: CredentialList,
        responseType: String? = "vp_token",
        responseMode: String = "direct_post",
        transactionData: List<String>? = null,
        clientMetadata: Any? = null,
    ) = PresentationRequest(
        clientId = CLIENT_ID,
        nonce = NONCE,
        state = STATE,
        responseType = responseType,
        responseMode = responseMode,
        responseUri = RESPONSE_URI,
        dcqlQuery = DCQL(credentials = entries.toList()),
        transactionDdata = transactionData?.let { ArrayList(it) },
        clientMetaDetails = clientMetadata,
    )

    // --- Transaction data and client metadata ---

    /** One `transaction_data` entry: base64url JSON naming [type] and the credential ids it binds to. */
    fun transactionData(type: String, vararg credentialIds: String): String {
        val json = """{"type":"$type","credential_ids":[${credentialIds.joinToString(",") { "\"$it\"" }}]}"""
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.toByteArray())
    }

    fun verifierEncryptionKey(): ECKey =
        ECKeyGenerator(Curve.P_256).keyID("verifier-enc").keyUse(KeyUse.ENCRYPTION).generate()

    /** Client metadata with an embedded JWKS, as Gson hands it to the SDK (a map, not a typed object). */
    fun encryptionMetadata(
        key: ECKey,
        enc: String? = "A128GCM",
        alg: String? = null,
        version: String? = null,
    ): Map<String, Any?> {
        val publicJwk = JsonParser.parseString(key.toPublicJWK().toJSONString()).asJsonObject
        val keyMap = publicJwk.entrySet().associate { (k, v) -> k to v.asString }
        return linkedMapOf<String, Any?>("jwks" to mapOf("keys" to listOf(keyMap))).apply {
            enc?.let { put("authorization_encrypted_response_enc", it) }
            alg?.let { put("authorization_encrypted_response_alg", it) }
            version?.let { put("version", it) }
        }
    }

    // --- Reading results ---

    fun json(text: String?): JsonElement = JsonParser.parseString(text)

    /** The key binding JWT appended after the last `~` of a presented SD-JWT. */
    fun keyBindingJwt(presented: String): SignedJWT = SignedJWT.parse(presented.substringAfterLast("~"))
}
