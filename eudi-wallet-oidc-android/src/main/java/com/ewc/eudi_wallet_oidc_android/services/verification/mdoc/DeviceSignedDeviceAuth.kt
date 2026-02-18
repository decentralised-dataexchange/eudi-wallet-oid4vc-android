package com.ewc.eudi_wallet_oidc_android.services.verification.mdoc

import android.util.Log
import co.nstant.`in`.cbor.model.*
import co.nstant.`in`.cbor.model.Array
import org.spongycastle.asn1.ASN1Integer
import org.spongycastle.asn1.ASN1Sequence
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

fun createDeviceSignedCose(
    privateKey: PrivateKey,
    sessionTranscriptCbor: Array,
    namespaces: DataItem  // should already be #6.24 tagged bstr from createTaggedEmptyNamespaces()
): CborArray {

    // 1. Protected header: { 1: -7 } (ES256)
    val protectedHeader = Map().apply {
        put(UnsignedInteger(1), NegativeInteger(-7))
    }
    val protectedBytes = encodeToCborBytes(protectedHeader)

    // 2. DeviceNameSpacesBytes — if namespaces is already a tagged bstr, use directly
    //    If it's a raw Map, wrap it here:
    // val namespacesTagged = ByteString(encodeToCborBytes(namespaces)).also { it.setTag(24) }

    // 3. Build DeviceAuthentication array
    val deviceAuthentication = CborArray().apply {
        add(UnicodeString("DeviceAuthentication"))
        add(sessionTranscriptCbor)
        add(UnicodeString("eu.europa.ec.eudi.pid.1"))
        add(namespaces)  // must be #6.24 tagged bstr
    }

    // 4. Wrap DeviceAuthentication as #6.24 tagged bstr
    val deviceAuthenticationBytes = encodeToCborBytes(deviceAuthentication)
    val deviceAuthTagged = ByteString(deviceAuthenticationBytes).also { it.setTag(24) }

    // 5. Build Sig_Structure
    val sigStructure = CborArray().apply {
        add(UnicodeString("Signature1"))
        add(ByteString(protectedBytes))
        add(ByteString(ByteArray(0)))                         // external_aad = h''
        add(ByteString(deviceAuthenticationBytes))            // detached payload (NOT tagged here)
    }

    // 6. Sign
    val sigStructureBytes = encodeToCborBytes(sigStructure)
    val signatureBytes = signEs256(privateKey, sigStructureBytes)

    // 7. Build COSE_Sign1 — payload is detached (null)
    return CborArray().apply {
        add(ByteString(protectedBytes))
        add(Map())                   // unprotected: empty map
        add(SimpleValue.NULL)        // payload: detached
        add(ByteString(signatureBytes))
    }
}

/**
 * Signs data for ES256 (P-256) in the format required by COSE/mdoc.
 */
fun signEs256(privateKey: PrivateKey, sigStructureData: ByteArray): ByteArray {
    // 1. Sign using standard DER format
    val dsa = Signature.getInstance("SHA256withECDSA")
    dsa.initSign(privateKey)
    dsa.update(sigStructureData)
    val derSignature = dsa.sign()

    // 2. Convert DER to Raw (R + S)
    return derToP1363(derSignature, 32)
}

fun derToP1363(der: ByteArray, size: Int): ByteArray {
    val seq = ASN1Sequence.getInstance(der)
    val r = ASN1Integer.getInstance(seq.getObjectAt(0)).value
    val s = ASN1Integer.getInstance(seq.getObjectAt(1)).value

    val raw = ByteArray(size * 2)

    // Helper to insert BigInteger into fixed-size byte array
    val rBytes = r.toByteArray().filterIndexed { i, b -> !(i == 0 && b == 0.toByte()) }.toByteArray()
    val sBytes = s.toByteArray().filterIndexed { i, b -> !(i == 0 && b == 0.toByte()) }.toByteArray()

    System.arraycopy(rBytes, 0, raw, size - rBytes.size, rBytes.size)
    System.arraycopy(sBytes, 0, raw, size * 2 - sBytes.size, sBytes.size)

    return raw
}
