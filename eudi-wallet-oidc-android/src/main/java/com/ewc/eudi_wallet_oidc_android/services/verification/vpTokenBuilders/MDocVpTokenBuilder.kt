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
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

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

//        val handoverCbor = run {
//            val handoverMap = co.nstant.`in`.cbor.model.Map().apply {
//                put(co.nstant.`in`.cbor.model.UnicodeString("client_id"), co.nstant.`in`.cbor.model.UnicodeString(presentationRequest.clientId))
//                put(co.nstant.`in`.cbor.model.UnicodeString("nonce"), co.nstant.`in`.cbor.model.UnicodeString(presentationRequest.nonce))
//                put(co.nstant.`in`.cbor.model.UnicodeString("response_uri"), co.nstant.`in`.cbor.model.UnicodeString(presentationRequest.responseUri))
//            }
//            val baos = java.io.ByteArrayOutputStream()
//            co.nstant.`in`.cbor.CborEncoder(baos).encode(handoverMap)
//            baos.toByteArray()
//        }
//
//       val sessionTranscript = co.nstant.`in`.cbor.model.Array().apply {
//            add(co.nstant.`in`.cbor.model.SimpleValue.NULL) // DeviceEngagementBytes
//            add(co.nstant.`in`.cbor.model.SimpleValue.NULL) // EReaderKeyBytes
//            add(co.nstant.`in`.cbor.model.ByteString(handoverCbor)) // handover CBOR bytes as bstr
//        }
//
//        val baosSession = java.io.ByteArrayOutputStream()
//        co.nstant.`in`.cbor.CborEncoder(baosSession).encode(sessionTranscript)
//        val sessionTranscriptCbor = baosSession.toByteArray()

        val sessionTranscript = buildSessionTranscriptForRedirect(
            clientId = presentationRequest.clientId ?:"",
            nonce = presentationRequest.nonce?:"",
            jwkThumbprint = null, // 32 bytes, or null
            responseUri = presentationRequest.redirectUri?:""
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

//        val handoverCbor = run {
//            val handoverMap = co.nstant.`in`.cbor.model.Map().apply {
//                put(co.nstant.`in`.cbor.model.UnicodeString("client_id"), co.nstant.`in`.cbor.model.UnicodeString(presentationRequest.clientId))
//                put(co.nstant.`in`.cbor.model.UnicodeString("nonce"), co.nstant.`in`.cbor.model.UnicodeString(presentationRequest.nonce))
//                put(co.nstant.`in`.cbor.model.UnicodeString("response_uri"), co.nstant.`in`.cbor.model.UnicodeString(presentationRequest.responseUri))
//            }
//            val baos = java.io.ByteArrayOutputStream()
//            co.nstant.`in`.cbor.CborEncoder(baos).encode(handoverMap)
//            baos.toByteArray()
//        }

//        val sessionTranscript = co.nstant.`in`.cbor.model.Array().apply {
//            add(co.nstant.`in`.cbor.model.SimpleValue.NULL) // DeviceEngagementBytes
//            add(co.nstant.`in`.cbor.model.SimpleValue.NULL) // EReaderKeyBytes
//            add(co.nstant.`in`.cbor.model.ByteString(handoverCbor)) // handover CBOR bytes as bstr
//        }

        val sessionTranscript = buildSessionTranscriptForRedirect(
            clientId = presentationRequest.clientId ?:"",
            nonce = presentationRequest.nonce?:"",
            jwkThumbprint = null, // 32 bytes, or null
            responseUri = presentationRequest.redirectUri?:""
        )

//        val baosSession = java.io.ByteArrayOutputStream()
//        co.nstant.`in`.cbor.CborEncoder(baosSession).encode(sessionTranscript)
//        val sessionTranscriptCbor = baosSession.toByteArray()

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

    fun buildSessionTranscriptForRedirect(
        clientId: String,
        nonce: String,
        jwkThumbprint: ByteArray?, // null if response not encrypted
        responseUri: String
    ): ByteArray {

        // 1. Encode handover info
        val infoBytes = buildOpenID4VPHandoverInfo(
            clientId = clientId,
            nonce = nonce,
            jwkThumbprint = jwkThumbprint,
            responseUri = responseUri
        )

        // 2. Hash it
        val infoHash = sha256(infoBytes)

        // 3. Build OpenID4VPHandover
        val handoverBytes = buildOpenID4VPHandover(infoHash)

        // 4. Build SessionTranscript
        return buildSessionTranscript(handoverBytes)
    }

    fun buildSessionTranscript(handoverBytes: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream()

        val builder = CborBuilder()
        val array = builder.addArray()
        array.add(SimpleValue.NULL) // DeviceEngagementBytes = null
        array.add(SimpleValue.NULL) // EReaderKeyBytes = null

        // The handover is a CBOR structure, so embed raw CBOR bytes
        array.add(ByteString(handoverBytes))

        array.end()

        CborEncoder(baos).encode(builder.build())
        return baos.toByteArray()
    }

    fun buildOpenID4VPHandover(infoHash: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream()

        val builder = CborBuilder()
        val array = builder.addArray()
        array.add("OpenID4VPHandover")
        array.add(ByteString(infoHash))
        array.end()

        CborEncoder(baos).encode(builder.build())
        return baos.toByteArray()
    }

    fun sha256(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(data)
    }

    fun buildOpenID4VPHandoverInfo(
        clientId: String,
        nonce: String,
        jwkThumbprint: ByteArray?, // null if not encrypted
        responseUri: String
    ): ByteArray {
        val baos = ByteArrayOutputStream()

        val builder = CborBuilder()
        val array = builder.addArray()
        array.add(clientId)
        array.add(nonce)

        if (jwkThumbprint != null) {
            array.add(ByteString(jwkThumbprint))
        } else {
            array.add(SimpleValue.NULL)
        }

        array.add(responseUri)
        array.end()

        CborEncoder(baos).encode(builder.build())
        return baos.toByteArray()
    }
}