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
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec

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
        val deviceSigned = createDeviceSigned(jwk)

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

        val deviceSigned = createDeviceSigned(jwk)

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
}