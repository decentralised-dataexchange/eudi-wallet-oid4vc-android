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
import com.nimbusds.jose.jwk.JWK
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import co.nstant.`in`.cbor.model.*
import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.CborEncoder
import com.ewc.eudi_wallet_oidc_android.models.DeviceSigned
import com.ewc.eudi_wallet_oidc_android.services.verification.ResponseModes
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse.VerifierJwk
import com.ewc.eudi_wallet_oidc_android.services.verification.deviceSigned.JWKThumbprint
import com.ewc.eudi_wallet_oidc_android.services.verification.deviceSigned.buildDeviceAuthenticationBytes
import com.ewc.eudi_wallet_oidc_android.services.verification.deviceSigned.buildDeviceSignatureCoseSign1
import com.ewc.eudi_wallet_oidc_android.services.verification.deviceSigned.buildProtectedHeader
import com.ewc.eudi_wallet_oidc_android.services.verification.deviceSigned.buildSessionTranscriptForOpenID4VP
import com.ewc.eudi_wallet_oidc_android.services.verification.deviceSigned.encodeEmptyDeviceNameSpaces
import com.ewc.eudi_wallet_oidc_android.services.verification.mdoc.toHex
import com.google.gson.Gson
import com.nimbusds.jose.util.Base64URL
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

class MDocVpTokenBuilder : VpTokenBuilder {
    override suspend fun build(
        credentialList: List<String>?,
        presentationRequest: PresentationRequest?,
        did: String?,
        jwk: JWK?,
        inputDescriptors: Any?,
        isScaFlow: Boolean
    ): String? {
        var processPresentationDefinition: PresentationDefinition? = null
        if (presentationRequest == null) return null
        if (presentationRequest?.dcqlQuery == null) {
            processPresentationDefinition = processPresentationDefinition(
                presentationRequest.presentationDefinition
            )
        }

        val documentList = mutableListOf<Document>()

        val clientJWK = try {
            val gson = Gson()
            val clientMetadataJson = gson.toJsonTree(presentationRequest.clientMetaDetails).asJsonObject
            val jweAlgorithm = VerifierJwk.deriveJWEAlgorithmFromClientMetadata(clientMetadataJson)
            VerifierJwk.deriveVerifiersJWKFromClientMetadata(clientMetadataJson, jweAlgorithm)
        } catch (e: Exception) {
            null
        }
        val sessionTranscript = buildSessionTranscriptForOpenID4VP(
            clientId = presentationRequest.clientId ?: "",
            nonce = presentationRequest.nonce ?: "",
            jwkThumbprint = clientJWK?.let { JWKThumbprint.computeJwkThumbprintBytes(it) },
            responseUri = if (presentationRequest.responseMode == ResponseModes.DC_API.value || presentationRequest.responseMode == ResponseModes.DC_API_JWT.value)
                null
            else presentationRequest.responseUri ?: presentationRequest.redirectUri ?: "",
            responseMode = presentationRequest.responseMode
        )

        val emptyNameSpace = encodeEmptyDeviceNameSpaces()

        val protectedArray = buildProtectedHeader()

        val ecJwk = jwk?.toECKey()

        // ---- Public Key ----
        val publicKey = ecJwk?.toPublicKey() as ECPublicKey
        val publicKeyEncoded = publicKey.encoded
        Log.d("Device signing", "Public Key (X.509 DER, hex): ${publicKeyEncoded.toHex()}")


        // ---- Private Key ----
        val privateKey = ecJwk.toPrivateKey() as ECPrivateKey
        val privateKeyEncoded = privateKey.encoded
        Log.d("Device signing", "Private Key (PKCS#8 DER, hex): ${privateKeyEncoded.toHex()}")
        credentialList?.forEach { credential ->
            val singleList = listOf(credential)
            val docType = CborUtils.extractDocTypeFromIssuerAuth(singleList)
                ?: processPresentationDefinition?.docType

            val issuerAuth = CborUtils.processExtractIssuerAuth(singleList)

            val nameSpaces = CborUtils.processExtractNameSpaces(singleList, presentationRequest)

            val deviceAuthBytes = buildDeviceAuthenticationBytes(
                sessionTranscriptArray = sessionTranscript.first,
                docType = docType ?: "",
                deviceNameSpacesBytes = emptyNameSpace
            )

            val sig = buildDeviceSignatureCoseSign1(deviceAuthBytes, protectedArray, privateKey)

            val deviceSigned = DeviceSigned(emptyNameSpace, Map().apply { put(UnicodeString("deviceSignature"), sig) })

            documentList.add(
                Document(
                    docType = docType ?: "",
                    issuerSigned = IssuerSigned(nameSpaces, issuerAuth),
                    deviceSigned = deviceSigned
                )
            )
        }

        val generatedVpToken = VpToken(
            version = "1.0", documents = documentList, status = 0
        )

        val encoded = CborUtils.encodeMDocToCbor(generatedVpToken)
        val cborToken =
            Base64.encodeToString(encoded, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        return cborToken
    }

    /**
     * Computes the JWK Thumbprint (RFC 7638) of a [JWK] as raw SHA-256 bytes.
     *
     * This is what the verifier calls `jwk_thumbprint_bytes` — the raw 32-byte
     * SHA-256 digest that goes into OpenID4VPHandoverInfo as a CBOR bstr.
     *
     * Nimbus provides [JWK.computeThumbprint] which returns the thumbprint as a
     * Base64URL string. We decode that back to raw bytes here, matching exactly
     * what the Python verifier does:
     *
     *   padded = jwk_thumbprint + "=" * padding
     *   jwk_thumbprint_bytes = base64.urlsafe_b64decode(padded)
     *
     * @param jwk The JWK whose thumbprint to compute (EC, RSA, OKP, etc.)
     * @return Raw 32-byte SHA-256 thumbprint (bstr for CBOR encoding).
     * @throws JOSEException if the thumbprint cannot be computed.
     */
    fun computeJwkThumbprintBytes(jwk: JWK): ByteArray {
        // Nimbus computes RFC 7638 thumbprint: SHA-256 of canonical JSON members.
        // Returns a Base64URL-encoded string (no padding).
        val thumbprintBase64Url: Base64URL = jwk.computeThumbprint("SHA-256")

        // Decode Base64URL → raw bytes (these are the 32 SHA-256 hash bytes).
        return thumbprintBase64Url.decode()
    }

    /**
     * Convenience overload — returns the thumbprint as a Base64URL [String]
     * (no padding), e.g. for logging or JWK "kid" assignment.
     */
    fun computeJwkThumbprintBase64Url(jwk: JWK): String {
        return jwk.computeThumbprint("SHA-256").toString()
    }

    fun generateEphemeralEcKey(): KeyPair {
        val keyGen = KeyPairGenerator.getInstance("EC")
        val ecSpec = ECGenParameterSpec("secp256r1") // = P-256
        keyGen.initialize(ecSpec)
        return keyGen.generateKeyPair()
    }


    override suspend fun buildV2(
        credentialList: List<String>?,
        presentationRequest: PresentationRequest?,
        did: String?,
        jwk: JWK?,
        inputDescriptors: Any?,
        isScaFlow: Boolean
    ): List<String?> {
        var processPresentationDefinition: PresentationDefinition? = null
        if (presentationRequest == null) return listOf()
        if (presentationRequest?.dcqlQuery == null) {
            processPresentationDefinition = processPresentationDefinition(
                presentationRequest.presentationDefinition
            )
        }

        val documentList = mutableListOf<Document>()
        val issuerAuth = CborUtils.processExtractIssuerAuth(credentialList)
        val docType = CborUtils.extractDocTypeFromIssuerAuth(credentialList)
            ?: processPresentationDefinition?.docType
        val nameSpaces = CborUtils.processExtractNameSpaces(
            credentialList, presentationRequest
        )
        val issuerSigned = IssuerSigned(
            nameSpaces = nameSpaces, issuerAuth = issuerAuth
        )

        val clientJWK = try {
            val gson = Gson()
            val clientMetadataJson = gson.toJsonTree(presentationRequest.clientMetaDetails).asJsonObject
            val jweAlgorithm = VerifierJwk.deriveJWEAlgorithmFromClientMetadata(clientMetadataJson)
            VerifierJwk.deriveVerifiersJWKFromClientMetadata(clientMetadataJson, jweAlgorithm)
        } catch (e: Exception) {
            null
        }
        val sessionTranscript = buildSessionTranscriptForOpenID4VP(
            clientId = presentationRequest.clientId ?: "",
            nonce = presentationRequest.nonce ?: "",
            responseUri =  if (presentationRequest.responseMode == ResponseModes.DC_API.value || presentationRequest.responseMode == ResponseModes.DC_API_JWT.value)
                null
            else presentationRequest.responseUri ?: presentationRequest.redirectUri ?: "",
            jwkThumbprint = clientJWK?.let { JWKThumbprint.computeJwkThumbprintBytes(it) },
            responseMode = presentationRequest.responseMode
        )

        val emptyNameSpace = encodeEmptyDeviceNameSpaces()

        val deviceAuthentication = buildDeviceAuthenticationBytes(
            sessionTranscriptArray = sessionTranscript.first,
            docType = docType ?:"",
            deviceNameSpacesBytes = emptyNameSpace
        )

        val protectedArray = buildProtectedHeader()

        val ecJwk = jwk?.toECKey()

        // ---- Public Key ----
        val publicKey = ecJwk?.toPublicKey() as ECPublicKey
        val publicKeyEncoded = publicKey.encoded
        Log.d("Device signing", "Public Key (X.509 DER, hex): ${publicKeyEncoded.toHex()}")


        // ---- Private Key ----
        val privateKey = ecJwk.toPrivateKey() as ECPrivateKey
        val privateKeyEncoded = privateKey.encoded
        Log.d("Device signing", "Private Key (PKCS#8 DER, hex): ${privateKeyEncoded.toHex()}")

        val sig = buildDeviceSignatureCoseSign1(
            deviceAuthenticationBytes = deviceAuthentication,
            protectedHeaderBytes = protectedArray,
            privateKey = privateKey
        )

        val deviceAuth = Map().apply {
            put(UnicodeString("deviceSignature"), sig)
        }
        val deviceSigned = DeviceSigned(emptyNameSpace, deviceAuth)

        val inputDescriptorSize = if (presentationRequest?.dcqlQuery != null) {
            presentationRequest?.dcqlQuery?.credentials?.size
        } else {
            processPresentationDefinition?.inputDescriptors?.size
        } ?: 0
        repeat(inputDescriptorSize) {
            documentList.add(
                Document(
                    docType = docType ?: "",
                    issuerSigned = issuerSigned,
                    deviceSigned = deviceSigned
                )
            )
        }

        val generatedVpToken = VpToken(
            version = "1.0", documents = documentList, status = 0
        )

        val encoded = CborUtils.encodeMDocToCbor(generatedVpToken)
        val cborToken =
            Base64.encodeToString(encoded, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

        return listOf(cborToken)
    }

    fun buildSessionTranscriptFor18013_7(
        clientId: String,
        nonce: String,
        responseUri: String
    ): Pair<co.nstant.`in`.cbor.model.Array, ByteArray> {
        val (handover, handoverBytes) = buildOpenID4VPHandoverInfo(
            clientId = clientId,
            nonce = nonce,
            responseUri = responseUri
        )
        val (sessionTranscript, sessionTranscriptBytes) = buildSessionTranscript(handover)
        return Pair(sessionTranscript, sessionTranscriptBytes)
    }

    fun buildSessionTranscriptForRedirect(
        clientId: String,
        nonce: String,
        jwkThumbprint: ByteArray?, // null if response not encrypted
    ): co.nstant.`in`.cbor.model.Array {

        // 1. Encode handover info
        val infoBytes = buildOpenID4VPHandoverInfoRedirect(
            clientId = clientId,
            nonce = nonce,
            jwkThumbprint = jwkThumbprint,
        )

        // 2. Hash it
        val infoHash = sha256(infoBytes)

        // 3. Build OpenID4VPHandover
        val handoverBytes = buildOpenID4VPHandoverRedirect(infoHash)

        // 4. Build SessionTranscript
        return buildSessionTranscriptRedirect(handoverBytes)
    }

    fun buildSessionTranscriptRedirect(handoverBytes: ByteArray): co.nstant.`in`.cbor.model.Array {
        val baos = ByteArrayOutputStream()

        val builder = CborBuilder()
        val array = builder.addArray()
        array.add(SimpleValue.NULL) // DeviceEngagementBytes = null
        array.add(SimpleValue.NULL) // EReaderKeyBytes = null

        // The handover is a CBOR structure, so embed raw CBOR bytes
        array.add(ByteString(handoverBytes))

        array.end()

        val dataItems = builder.build()
        val sessionTranscriptArray =
            dataItems.first() as co.nstant.`in`.cbor.model.Array

        CborEncoder(baos).encode(builder.build())
        return sessionTranscriptArray
    }

    fun buildOpenID4VPHandoverRedirect(infoHash: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream()

        val builder = CborBuilder()
        val array = builder.addArray()
        array.add("OpenID4VPDCAPIHandover")
        array.add(ByteString(infoHash))
        array.end()

        CborEncoder(baos).encode(builder.build())
        return baos.toByteArray()
    }

    fun buildOpenID4VPHandoverInfoRedirect(
        clientId: String,
        nonce: String,
        jwkThumbprint: ByteArray?, // null if not encrypted
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

        array.end()

        CborEncoder(baos).encode(builder.build())
        return baos.toByteArray()
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

        // clientIdHash = SHA-256(CBOR([clientId, mdocGeneratedNonce]))
        val clientIdHash = sha256(
            cborArrayBytes(clientId, mdocGeneratedNonce)
        )

        // responseUriHash = SHA-256(CBOR([responseUri, mdocGeneratedNonce]))
        val responseUriHash = sha256(
            cborArrayBytes(responseUri, mdocGeneratedNonce)
        )

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