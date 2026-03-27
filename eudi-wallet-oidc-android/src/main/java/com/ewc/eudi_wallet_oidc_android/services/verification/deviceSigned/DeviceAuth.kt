package com.ewc.eudi_wallet_oidc_android.services.verification.deviceSigned

import android.util.Log
import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.UnicodeString
import com.ewc.eudi_wallet_oidc_android.services.verification.mdoc.signEs256
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.PrivateKey

import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.UnsignedInteger
import com.ewc.eudi_wallet_oidc_android.services.verification.ResponseModes

// ═══════════════════════════════════════════════════════════════════════════════
// ISO 18013-5 §9.1.5.1 — SessionTranscript (OpenID4VP / redirect flow)
//
// The ISO spec defines SessionTranscript for device retrieval as:
//   SessionTranscript = [DeviceEngagementBytes, EReaderKeyBytes, Handover]
//
// For OpenID4VP (no BLE/NFC engagement), per OID4VP §B.2.6.1:
//   SessionTranscript = [null, null, OpenID4VPHandover]
//   OpenID4VPHandover = ["OpenID4VPHandover", SHA-256(HandoverInfoBytes)]
//   OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint, responseUri]
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Builds the full SessionTranscript for the OpenID4VP redirect flow.
 *
 * Per ISO 18013-5 §9.1.5.1 + OID4VP Appendix B.2.6.1:
 *   SessionTranscript = [null, null, OpenID4VPHandover]
 *
 * @param clientId      client_id from the Authorization Request (tstr)
 * @param nonce         nonce from the Authorization Request (tstr)
 * @param responseUri   response_uri from the Authorization Request (tstr)
 * @param jwkThumbprint Raw SHA-256 bytes of the reader ephemeral JWK, or
 *                      null for direct_post (unencrypted) mode.
 *
 * @return Pair of (SessionTranscript as CborArray DataItem, CBOR-encoded bytes)
 *         The CborArray is passed directly into DeviceAuthentication.
 *         The bytes are used for HKDF salt: SHA-256(SessionTranscriptBytes).
 */

fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }

fun buildSessionTranscriptForOpenID4VP(
    clientId: String,
    nonce: String,
    responseUri: String? = null,
    jwkThumbprint: ByteArray? = null,
    responseMode: String?
): Pair<CborArray, ByteArray> {
    val TAG = "SessionTranscript"

    // Step 1: HandoverInfo = [clientId, nonce, jwkThumbprint, responseUri]
    val handoverInfo = if (responseUri != null) {
        CborArray().apply {
            add(UnicodeString(clientId))
            add(UnicodeString(nonce))
            add(if (jwkThumbprint != null) ByteString(jwkThumbprint) else SimpleValue.NULL)
            add(UnicodeString(responseUri))
        }
    } else {
        CborArray().apply {
            add(UnicodeString(clientId))
            add(UnicodeString(nonce))
            add(if (jwkThumbprint != null) ByteString(jwkThumbprint) else SimpleValue.NULL)
        }
    }
    val handoverInfoBytes = encodeCbor(handoverInfo)
//    Log.d(TAG, "HandoverInfo Bytes (Hex): ${handoverInfoBytes.toHexString()}")

    // Step 2: Hash HandoverInfo
    val handoverInfoHash = MessageDigest.getInstance("SHA-256").digest(handoverInfoBytes)
//    Log.d(TAG, "HandoverInfo Hash (Hex): ${handoverInfoHash.toHexString()}")

    // Step 3: OpenID4VPHandover = ["OpenID4VPHandover", hash]
    val handoverArray = CborArray().apply {
        add(if (responseMode == ResponseModes.DC_API.value ||
            responseMode == ResponseModes.DC_API_JWT.value) UnicodeString("OpenID4VPHandover")
                else UnicodeString("OpenID4VPHandover"))
        add(ByteString(handoverInfoHash))
    }
//    Log.d(TAG, "OpenID4VPHandover Array (Hex): ${encodeCbor(handoverArray).toHexString()}")

    // Step 4: SessionTranscript = [null, null, OpenID4VPHandover]
    val stArray = CborArray().apply {
        add(SimpleValue.NULL) // DeviceEngagement
        add(SimpleValue.NULL) // EReaderKey
        add(handoverArray)    // Handover
    }

    val finalSessionTranscriptBytes = encodeCbor(stArray)
//    Log.d(TAG, "Final SessionTranscript (Hex): ${finalSessionTranscriptBytes.toHexString()}")

    return Pair(stArray, finalSessionTranscriptBytes)
}

private fun encodeCbor(dataItem: co.nstant.`in`.cbor.model.DataItem): ByteArray {
    val baos = ByteArrayOutputStream()
    CborEncoder(baos).encode(dataItem)
    return baos.toByteArray()
}

// ═══════════════════════════════════════════════════════════════════════════════
// ISO 18013-5 §9.1.3.4 + §9.1.3.6 — DeviceAuthentication + COSE_Sign1
//
// Spec (§9.1.3.4):
//   DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
//   DeviceAuthentication = [
//     "DeviceAuthentication",
//     SessionTranscript,        ; CborArray — NOT bstr-wrapped here
//     DocType,                  ; tstr
//     DeviceNameSpacesBytes     ; #6.24(bstr .cbor DeviceNameSpaces)
//   ]
//
// Spec (§9.1.3.6):
//   DeviceSignature = COSE_Sign1  (untagged)
//   - payload: null (detached)
//   - detached content: DeviceAuthenticationBytes
//   - external_aad: h'' (empty)
//   - protected header: { alg: ES256 (-7) }
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Builds DeviceAuthenticationBytes per ISO 18013-5 §9.1.3.4.
 *
 * This is the detached payload that gets signed in the COSE_Sign1.
 *
 * @param sessionTranscriptArray CborArray DataItem from buildSessionTranscriptForOpenID4VP()
 * @param docType                e.g. "eu.europa.ec.eudi.pid.1"
 * @param deviceNameSpacesBytes  #6.24(bstr .cbor DeviceNameSpaces) — use encodeEmptyNamespaces()
 *                               if no device-signed elements.
 * @return CBOR encoding of #6.24(bstr .cbor DeviceAuthentication)
 */
fun buildDeviceAuthenticationBytes(
    sessionTranscriptArray: CborArray,
    docType: String,
    deviceNameSpacesBytes: ByteString   // must already be tag-24 wrapped
): ByteArray {
    val TAG = "DeviceAuth"

    // 1. Inner: DeviceAuthentication array
    // [ "DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes ]
    val innerBaos = ByteArrayOutputStream()
    val builder = CborBuilder()
    val deviceAuthenticationArray = builder.addArray()
        .add(UnicodeString("DeviceAuthentication"))
        .add(sessionTranscriptArray)          // inline CborArray per spec
        .add(UnicodeString(docType))
        .add(deviceNameSpacesBytes)           // #6.24 tagged bstr
        .end()
        .build()

    CborEncoder(innerBaos).encode(deviceAuthenticationArray)
    val innerBytes = innerBaos.toByteArray()

//    Log.d(TAG, "DeviceAuthentication Array (Inner Hex): ${innerBytes.toHexString()}")

    // 2. Outer: wrap as #6.24(bstr .cbor DeviceAuthentication)
    // This is what ISO 18013-5 §9.1.3.4 calls 'DeviceAuthenticationBytes'
    val tagged = ByteString(innerBytes).also { it.setTag(24) }

    val outerBaos = ByteArrayOutputStream()
    CborEncoder(outerBaos).encode(tagged)
    val deviceAuthenticationBytes = outerBaos.toByteArray()

//    Log.d(TAG, "DeviceAuthenticationBytes (Tagged Hex): ${deviceAuthenticationBytes.toHexString()}")

    return deviceAuthenticationBytes
}

/**
 * Encodes DeviceNameSpaces as an empty map wrapped in tag-24.
 *
 * Per spec §8.3.2.1.2.2:
 *   DeviceNameSpacesBytes = #6.24(bstr .cbor DeviceNameSpaces)
 *   DeviceNameSpaces = {}   (empty map if no device-signed elements)
 */
fun encodeEmptyDeviceNameSpaces(): ByteString {
    val baos = ByteArrayOutputStream()
    CborEncoder(baos).encode(CborBuilder().addMap().end().build())
    return ByteString(baos.toByteArray()).also { it.setTag(24) }
}

/**
 * Builds an untagged COSE_Sign1 for DeviceSignature per ISO 18013-5 §9.1.3.6.
 *
 * Spec requirements:
 *   - payload: null (detached)
 *   - detached content: DeviceAuthenticationBytes
 *   - external_aad: h'' (empty bstr)
 *   - protected header: { 1: -7 }  (alg: ES256)
 *   - COSE_Sign1 is UNTAGGED (no CBOR tag 18)
 *
 * Sig_Structure (RFC 8152 §4.4):
 *   ["Signature1", protected, external_aad, payload]
 *   where payload = DeviceAuthenticationBytes (the tag-24 encoded bytes)
 *
 * @param deviceAuthenticationBytes Output of buildDeviceAuthenticationBytes()
 * @param protectedBytes            CBOR-encoded protected header { 1: -7 }
 * @param signFn                    Signing function: (bytesToSign) -> signature bytes
 * @return Untagged COSE_Sign1 as a CborArray DataItem
 */

/**
 * Builds the Protected Header: { 1: -7 } (alg: ES256)
 */
fun buildProtectedHeader(): ByteArray {
    val map = CborMap().apply {
        // Use explicit COSE types: 1 (alg) -> -7 (ES256)
        put(UnsignedInteger(1), NegativeInteger(-7))
    }
    return encodeCbor(map)
}

/**
 * Creates the COSE_Sign1 structure.
 */
fun buildDeviceSignatureCoseSign1(
    deviceAuthenticationBytes: ByteArray, // This is the #6.24(bstr)
    protectedHeaderBytes: ByteArray,
    privateKey: PrivateKey
): CborArray {
    val TAG = "CoseSign1"

    // 1. Construct Sig_Structure [ "Signature1", protected, external_aad, payload ]
    val sigStructure = CborArray().apply {
        add(UnicodeString("Signature1"))
        add(ByteString(protectedHeaderBytes))
        add(ByteString(ByteArray(0))) // empty external_aad
        add(ByteString(deviceAuthenticationBytes)) // THE PAYLOAD
    }

    // 2. Encode the Sig_Structure to bytes
    val toBeSigned = encodeCbor(sigStructure)
//    Log.d(TAG, "To-Be-Signed (Sig_Structure Hex): ${toBeSigned.toHexString()}")

    // 3. Sign and FORCE conversion to P1363 (64 bytes)
    val derSignature = signEs256(privateKey, toBeSigned)

    // Check if it's DER (starts with 0x30) and convert if necessary
    val signatureBytes = if (derSignature.size != 64 && derSignature[0] == 0x30.toByte()) {
        Log.w(TAG, "Detected DER signature (size ${derSignature.size}), converting to P1363...")
        convertDerToP1363(derSignature)
    } else {
        derSignature
    }

//    Log.d(TAG, "Final Signature (P1363 Hex): ${signatureBytes.toHexString()}")
//    Log.d(TAG, "Final Signature Length: ${signatureBytes.size} bytes")

    // 4. Final COSE_Sign1: [protected, unprotected, payload, signature]
    val coseSign1 = CborArray().apply {
        add(ByteString(protectedHeaderBytes)) // protected (bstr)
        add(CborMap())                        // unprotected (empty map)
        add(SimpleValue.NULL)                 // payload (detached)
        add(ByteString(signatureBytes))       // signature (bstr)
    }

    val finalCoseHex = encodeCbor(coseSign1).toHexString()
    Log.d(TAG, "Final COSE_Sign1 (Untagged Hex): $finalCoseHex")

    return coseSign1
}

/**
 * Converts a DER-encoded ECDSA signature to the P1363 (R|S) format.
 * ES256 requires exactly 64 bytes (32 for R, 32 for S).
 */
fun convertDerToP1363(der: ByteArray): ByteArray {
    val result = ByteArray(64)
    var offset = 0

    // Check for sequence header
    if (der[offset++] != 0x30.toByte()) throw IllegalArgumentException("Invalid DER signature")
    val seqLen = der[offset++].toInt() and 0xff

    // Read R
    if (der[offset++] != 0x02.toByte()) throw IllegalArgumentException("Invalid DER: R not found")
    var rLen = der[offset++].toInt() and 0xff
    var rOffset = offset
    offset += rLen

    // Handle R padding: skip leading zero byte if R is 33 bytes
    if (rLen > 32) {
        rOffset += (rLen - 32)
        rLen = 32
    }
    System.arraycopy(der, rOffset, result, 32 - rLen, rLen)

    // Read S
    if (der[offset++] != 0x02.toByte()) throw IllegalArgumentException("Invalid DER: S not found")
    var sLen = der[offset++].toInt() and 0xff
    var sOffset = offset

    // Handle S padding: skip leading zero byte if S is 33 bytes
    if (sLen > 32) {
        sOffset += (sLen - 32)
        sLen = 32
    }
    System.arraycopy(der, sOffset, result, 64 - sLen, sLen)

    return result
}