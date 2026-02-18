package com.ewc.eudi_wallet_oidc_android.services.verification.vpTokenBuilders

import android.util.Base64
import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.Document
import com.ewc.eudi_wallet_oidc_android.models.IssuerSigned
import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.VpToken
import com.ewc.eudi_wallet_oidc_android.services.utils.CborUtils
import com.ewc.eudi_wallet_oidc_android.services.verification.PresentationDefinitionProcessor.processPresentationDefinition
import com.ewc.eudi_wallet_oidc_android.services.verification.mdoc.createDeviceSigned
import com.nimbusds.jose.jwk.JWK
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import co.nstant.`in`.cbor.model.*
import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.CborEncoder
import com.nimbusds.jose.util.Base64URL
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom

class MDocVpTokenBuilder : VpTokenBuilder {
    override fun build(
        credentialList: List<String>?,
        presentationRequest: PresentationRequest?,
        did: String?,
        jwk: JWK?,
        inputDescriptors: Any?
    ): String? {
        var processPresentationDefinition: PresentationDefinition?=null
        if (presentationRequest == null) return null
        if (presentationRequest?.dcqlQuery==null) {
            processPresentationDefinition = processPresentationDefinition(
                presentationRequest.presentationDefinition
            )
        }

        val documentList = mutableListOf<Document>()
        val issuerAuth = CborUtils.processExtractIssuerAuth(credentialList)
        val docType = CborUtils.extractDocTypeFromIssuerAuth(credentialList) ?: processPresentationDefinition?.docType
        val nameSpaces = CborUtils.processExtractNameSpaces(
            credentialList, presentationRequest
        )
        val issuerSigned = IssuerSigned(
            nameSpaces = nameSpaces, issuerAuth = issuerAuth
        )
//        val keyPair = generateEphemeralEcKey()
//        val privateKey: PrivateKey = keyPair.private

        val (sessionTranscript, sessionTranscriptBytes) = buildSessionTranscriptFor18013_7(
            clientId = presentationRequest.clientId ?: "",
            nonce = presentationRequest.nonce ?: "",
            responseUri = presentationRequest.responseUri ?: presentationRequest.redirectUri ?: ""
        )

        val deviceSigned = createDeviceSigned(jwk, sessionTranscript)

        val inputDescriptorSize = if (presentationRequest?.dcqlQuery != null) {
            presentationRequest?.dcqlQuery?.credentials?.size
        } else {
            processPresentationDefinition?.inputDescriptors?.size
        } ?: 0
        repeat(inputDescriptorSize) {
            documentList.add(
                Document(
                    docType = docType ?: "", issuerSigned = issuerSigned, deviceSigned = deviceSigned
                )
            )
        }

        val generatedVpToken = VpToken(
            version = "1.0", documents = documentList, status = 0
        )

        val encoded = CborUtils.encodeMDocToCbor(generatedVpToken)
        val cborToken = Base64.encodeToString(encoded, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        return cborToken
    }

    fun computeJwkThumbprint(): ByteArray {
        // RFC 7638 – required EC members in lexicographic order
//        val kty = jwk["kty"] ?: throw IllegalArgumentException("Missing kty")
//
//        if (kty != "EC") {
//            throw IllegalArgumentException("Unsupported key type: $kty")
//        }


        val requiredMembers = mapOf(
            "kty" to "EC",
            "use" to "enc",
            "crv" to "P-256",
            "kid" to "405a5a9c-a70f-4844-bcfa-f379573202d9",
            "x" to "jxptvuIKEua5o2w7Y6ocLJn27hWQ5kKgEvauub2pNMU",
            "y" to "tn3mK-2IjyWLcrGGX5SnIZukfCiIe1nAGMLgdHj9CeU",
            "alg" to "ECDH-ES"
        )

        // Canonical JSON: sorted keys, no whitespace
        val canonicalJson = requiredMembers
            .toSortedMap()
            .entries
            .joinToString(
                prefix = "{",
                postfix = "}",
                separator = ","
            ) { (key, value) ->
                "\"$key\":\"$value\""
            }

        Log.d("Device signing", "computeJwkThumbprint: $canonicalJson")
        // UTF-8 bytes
        val jsonBytes = canonicalJson.toByteArray(StandardCharsets.UTF_8)

        // SHA-256 hash
        val digest = MessageDigest.getInstance("SHA-256")
        val thumbprint = digest.digest(jsonBytes)

        return thumbprint
    }

    fun generateEphemeralEcKey(): KeyPair {
        val keyGen = KeyPairGenerator.getInstance("EC")
        val ecSpec = ECGenParameterSpec("secp256r1") // = P-256
        keyGen.initialize(ecSpec)
        return keyGen.generateKeyPair()
    }


    override fun buildV2(
        credentialList: List<String>?,
        presentationRequest: PresentationRequest?,
        did: String?,
        jwk: JWK?,
        inputDescriptors: Any?
    ): List<String?> {
        var processPresentationDefinition: PresentationDefinition?=null
        if (presentationRequest == null) return listOf()
        if (presentationRequest?.dcqlQuery==null) {
            processPresentationDefinition = processPresentationDefinition(
                presentationRequest.presentationDefinition
            )
        }

        val documentList = mutableListOf<Document>()
        val issuerAuth = CborUtils.processExtractIssuerAuth(credentialList)
        val docType = CborUtils.extractDocTypeFromIssuerAuth(credentialList) ?: processPresentationDefinition?.docType
        val nameSpaces = CborUtils.processExtractNameSpaces(
            credentialList, presentationRequest
        )
        val issuerSigned = IssuerSigned(
            nameSpaces = nameSpaces, issuerAuth = issuerAuth
        )

        val (sessionTranscript, sessionTranscriptBytes) = buildSessionTranscriptFor18013_5(
            clientId = presentationRequest.clientId ?:"",
            nonce =presentationRequest.nonce?:"",
            responseUri = presentationRequest.responseUri?: presentationRequest.redirectUri?:""
        )
        val deviceSigned = createDeviceSigned(jwk, sessionTranscript)

        val inputDescriptorSize = if (presentationRequest?.dcqlQuery != null) {
            presentationRequest?.dcqlQuery?.credentials?.size
        } else {
            processPresentationDefinition?.inputDescriptors?.size
        } ?: 0
        repeat(inputDescriptorSize) {
            documentList.add(
                Document(
                    docType = docType ?: "", issuerSigned = issuerSigned, deviceSigned = deviceSigned
                )
            )
        }

        val generatedVpToken = VpToken(
            version = "1.0", documents = documentList, status = 0
        )

        val encoded = CborUtils.encodeMDocToCbor(generatedVpToken)
        val cborToken = Base64.encodeToString(encoded, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

        return listOf(cborToken)
    }

   fun buildSessionTranscriptFor18013_7(
       clientId: String,
       nonce: String,
       responseUri: String
    ): Pair<co.nstant.`in`.cbor.model.Array, ByteArray> {
        // 1. Encode handover info
        val (handover, handoverBytes) = buildOpenID4VPHandoverInfo(
            clientId = clientId,
            nonce = nonce,
            responseUri = responseUri
        )

       Log.d("buildSessionTranscriptFor18013_7", "Handover CBOR object     : $handover")
       Log.d(
           "buildSessionTranscriptFor18013_7",
           "Handover CBOR bytes len : ${handoverBytes.size}"
       )
       Log.d(
           "buildSessionTranscriptFor18013_7",
           "Handover CBOR bytes(hex): ${
               handoverBytes.joinToString("") { "%02x".format(it) }
           }"
       )
        // 4. Build SessionTranscript
        val (sessionTranscript, sessionTranscriptBytes) = buildSessionTranscript(handover)
       Log.d("buildSessionTranscriptFor18013_7", "SessionTranscript CBOR object     : $sessionTranscript")
       Log.d(
           "buildSessionTranscriptFor18013_7",
           "SessionTranscript bytes len      : ${sessionTranscriptBytes.size}"
       )
       Log.d(
           "buildSessionTranscriptFor18013_7",
           "SessionTranscript bytes (hex)    : ${
               sessionTranscriptBytes.joinToString("") { "%02x".format(it) }
           }"
       )

       Log.d("buildSessionTranscriptFor18013_7", "=== buildSessionTranscriptFor18013_5 END ===")
       return Pair(sessionTranscript, sessionTranscriptBytes)
    }

    fun buildSessionTranscriptFor18013_5(
        clientId: String,
        nonce: String,
        responseUri: String
    ): Pair<co.nstant.`in`.cbor.model.Array, ByteArray> {

        val tag = "Device Signing"

        Log.d(tag, "=== buildSessionTranscriptFor18013_5 START ===")
        Log.d(tag, "clientId     : $clientId")
        Log.d(tag, "nonce        : $nonce")
        Log.d(tag, "responseUri  : $responseUri")

        // 1. Build OpenID4VP Handover Info
        val (handover, handoverBytes) = buildOpenID4VPHandoverInfo(
            clientId = clientId,
            nonce = nonce,
            responseUri = responseUri
        )

        Log.d(tag, "Handover CBOR object     : $handover")
        Log.d(
            tag,
            "Handover CBOR bytes len : ${handoverBytes.size}"
        )
        Log.d(
            tag,
            "Handover CBOR bytes(hex): ${
                handoverBytes.joinToString("") { "%02x".format(it) }
            }"
        )

        // 2. Build SessionTranscript
        val (sessionTranscript, sessionTranscriptBytes) =
            buildSessionTranscript(handover)

        Log.d(tag, "SessionTranscript CBOR object     : $sessionTranscript")
        Log.d(
            tag,
            "SessionTranscript bytes len      : ${sessionTranscriptBytes.size}"
        )
        Log.d(
            tag,
            "SessionTranscript bytes (hex)    : ${
                sessionTranscriptBytes.joinToString("") { "%02x".format(it) }
            }"
        )

        Log.d(tag, "=== buildSessionTranscriptFor18013_5 END ===")

        return Pair(sessionTranscript, sessionTranscriptBytes)
    }


    fun buildSessionTranscript(handoverArray: co.nstant.`in`.cbor.model.Array): Pair<co.nstant.`in`.cbor.model.Array, ByteArray> {
        val baos = ByteArrayOutputStream()

        val builder = CborBuilder()
        val array = builder.addArray()
        array.add(SimpleValue.NULL) // DeviceEngagementBytes = null
        array.add(SimpleValue.NULL) // EReaderKeyBytes = null

        // The handover is a CBOR array structure, embed it directly
        array.add(handoverArray)

        array.end()

        val dataItems = builder.build()
        val sessionTranscriptArray =
            dataItems.first() as co.nstant.`in`.cbor.model.Array

        CborEncoder(baos).encode(dataItems)

        return Pair(sessionTranscriptArray, baos.toByteArray())
    }

   fun buildOpenID4VPHandover(infoHash: ByteArray): co.nstant.`in`.cbor.model.Array {
       val array = Array().apply {
           add(UnicodeString("OpenID4VPHandover"))
           add(ByteString(infoHash))
       }
       return array
   }

    fun sha256(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(data)
    }

//    fun buildOpenID4VPHandoverInfo(
//        clientId: Base64URL,
//        nonce: Base64URL,
//        jwkThumbprint: ByteArray?, // null if not encrypted
//        responseUri: String
//    ): ByteArray {
//        val baos = ByteArrayOutputStream()
//
//        val builder = CborBuilder()
//        val array = builder.addArray()
//        array.add(clientId.toString())
//        array.add(nonce.toString())
//
//        if (jwkThumbprint != null) {
//            array.add(ByteString(jwkThumbprint))
//        } else {
//            array.add(SimpleValue.NULL)
//        }
//
//        array.add(responseUri)
//        array.end()
//
//        CborEncoder(baos).encode(builder.build())
//        return baos.toByteArray()
//    }

    fun buildOpenID4VPHandoverInfo(
        clientId: String,
        nonce: String,
        responseUri: String
    ): Pair<co.nstant.`in`.cbor.model.Array, ByteArray> {

        // ⚠️ NOT spec-correct – should be cryptographically random
        val mdocGeneratedNonce = clientId

        Log.d("Device signing", "Mdoc generated nonce: $mdocGeneratedNonce")

        // clientIdHash = SHA-256(CBOR([clientId, mdocGeneratedNonce]))
        val clientIdHash = sha256(
            cborArrayBytes(clientId, mdocGeneratedNonce)
        )

        Log.d("Device Signing", "buildOpenID4VPHandoverInfo: ClientId Hash: ${String(clientIdHash)}")
        // responseUriHash = SHA-256(CBOR([responseUri, mdocGeneratedNonce]))
        val responseUriHash = sha256(
            cborArrayBytes(responseUri, mdocGeneratedNonce)
        )
        Log.d("Device Signing", "buildOpenID4VPHandoverInfo: response uri Hash: ${String(responseUriHash)}")

        // ---- Build CBOR ----
        val baos = ByteArrayOutputStream()
        val builder = CborBuilder()

        builder.addArray()
            .add(ByteString(clientIdHash))       // bstr
            .add(ByteString(responseUriHash))    // bstr
            .add(nonce)                          // tstr
            .end()

        val dataItems = builder.build()
        val handoverArray =
            dataItems.first() as co.nstant.`in`.cbor.model.Array

        CborEncoder(baos).encode(dataItems)

        return Pair(handoverArray, baos.toByteArray())
    }

    private fun cborArrayBytes(vararg values: String): ByteArray {
        val baos = ByteArrayOutputStream()
        val builder = CborBuilder()
        val array = builder.addArray()
        values.forEach { array.add(it) }
        array.end()
        CborEncoder(baos).encode(builder.build())
        return baos.toByteArray()
    }

    private fun generateMdocNonce(): String {
        val random = ByteArray(32) // 256-bit entropy (B.5.3 compliant)
        SecureRandom().nextBytes(random)
        return Base64URL.encode(random).toString()
    }

    private fun sha256X(input: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(input)
}