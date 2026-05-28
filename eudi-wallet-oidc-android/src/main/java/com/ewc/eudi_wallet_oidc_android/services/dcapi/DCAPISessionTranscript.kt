package com.ewc.eudi_wallet_oidc_android.services.dcapi

import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.UnicodeString
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * Builds the SessionTranscript for ISO 18013-7 Annex C (non-OpenID DC API).
 *
 * SessionTranscript = [null, null, ["dcapi", SHA-256(CBOR([encryptionInfoBase64, origin]))]]
 *
 * @param encryptionInfoBase64 The original base64url string from the request
 * @param origin The calling website origin (e.g., "https://example.com")
 * @return Pair of (SessionTranscript as CborArray, CBOR-encoded bytes)
 */
fun buildSessionTranscriptForDCAPI(
    encryptionInfoBase64: String,
    origin: String
): Pair<CborArray, ByteArray> {
    // Step 1: dcapiInfo = CBOR([encryptionInfoBase64, origin])
    val dcapiInfo = CborArray().apply {
        add(UnicodeString(encryptionInfoBase64))
        add(UnicodeString(origin))
    }
    val dcapiInfoBytes = encodeCborItem(dcapiInfo)

    // Step 2: SHA-256 hash
    val dcapiInfoHash = MessageDigest.getInstance("SHA-256").digest(dcapiInfoBytes)

    // Step 3: handover = ["dcapi", dcapiInfoHash]
    val handover = CborArray().apply {
        add(UnicodeString("dcapi"))
        add(ByteString(dcapiInfoHash))
    }

    // Step 4: SessionTranscript = [null, null, handover]
    val sessionTranscript = CborArray().apply {
        add(SimpleValue.NULL)
        add(SimpleValue.NULL)
        add(handover)
    }

    val sessionTranscriptBytes = encodeCborItem(sessionTranscript)
    return Pair(sessionTranscript, sessionTranscriptBytes)
}

private fun encodeCborItem(dataItem: co.nstant.`in`.cbor.model.DataItem): ByteArray {
    val baos = ByteArrayOutputStream()
    CborEncoder(baos).encode(dataItem)
    return baos.toByteArray()
}
