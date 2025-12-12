package com.ewc.eudi_wallet_oidc_android.services.verification.mdoc

import co.nstant.`in`.cbor.model.*
import java.security.Signature
import java.security.PrivateKey
import co.nstant.`in`.cbor.model.Array as CborArray

//fun createDeviceSignedCose(privateKey: PrivateKey, deviceNamespacesCbor: ByteArray): ByteArray {
//    // Protected header: {1: 2}  (alg: ES256)
//    val protected = Map().apply {
//        put(UnsignedInteger(1), UnsignedInteger(2))
//    }
//    val protectedBytes = encodeToCborBytes(protected)
//
//    // External AAD is empty
//    val externalAad = ByteArray(0)
//
//    // Sig_structure = ["Signature1", protected, external_aad, payload]
//    val sigStructure = Array()
//    sigStructure.add(UnicodeString("Signature1"))
//    sigStructure.add(ByteString(protectedBytes))
//    sigStructure.add(ByteString(externalAad))
//    sigStructure.add(ByteString(deviceNamespacesCbor))
//
//    val sigToBeSigned = encodeToCborBytes(sigStructure)
//
//    // Sign using ECDSA with SHA-256
//    val signatureBytes = signEs256(privateKey, sigToBeSigned)
//
//    // Build COSE_Sign1 = [ protected, unprotected, payload, signature ]
//    val coseSign1 = Array()
//    coseSign1.add(ByteString(protectedBytes)) // Protected
//    coseSign1.add(Map())                      // Unprotected (empty)
//    coseSign1.add(ByteString(deviceNamespacesCbor)) // Payload
//    coseSign1.add(ByteString(signatureBytes)) // Signature
//
//    return encodeToCborBytes(coseSign1)
//}

fun createDeviceSignedCose(privateKey: PrivateKey, sessionTranscriptCbor: ByteArray): CborArray {
    // Protected header: {1: -7} (alg: ES256)
    val protectedHeader = Map().apply {
        put(UnsignedInteger(1), NegativeInteger(-7)) // alg = ES256
    }
    val protectedBytes = encodeToCborBytes(protectedHeader)

    // External AAD is empty
    val externalAad = ByteArray(0)

    // Sig_structure = ["Signature1", protected, external_aad, payload]
    val sigStructure = CborArray().apply {
        add(UnicodeString("Signature1"))
        add(ByteString(protectedBytes))
        add(ByteString(externalAad))
        add(ByteString(sessionTranscriptCbor)) // payload = null
    }

    val sigToBeSigned = encodeToCborBytes(sigStructure)

    // Sign using ECDSA with SHA-256
    val signatureBytes = signEs256(privateKey, sigToBeSigned)

    // COSE_Sign1 = [ protected, unprotected, payload, signature ]
    return CborArray().apply {
        add(ByteString(protectedBytes)) // h'a10126'
        add(Map())                      // {}
        add(ByteString(sessionTranscriptCbor))           // null
        add(ByteString(signatureBytes)) // h'<signature>'
    }
}

fun signEs256(privateKey: PrivateKey, data: ByteArray): ByteArray {
    val signature = Signature.getInstance("SHA256withECDSA")
    signature.initSign(privateKey)
    signature.update(data)
    return signature.sign()
}
