package com.ewc.eudi_wallet_oidc_android.services.dcapi

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import java.io.ByteArrayInputStream

data class ParsedCOSEKey(
    val kty: Int,
    val crv: Int,
    val x: ByteArray,
    val y: ByteArray
) {
    fun toUncompressedPoint(): ByteArray {
        val point = ByteArray(65)
        point[0] = 0x04
        System.arraycopy(x, 0, point, 1, 32)
        System.arraycopy(y, 0, point, 33, 32)
        return point
    }
}

data class ParsedEncryptionInfo(
    val cipherSuiteIdentifier: String,
    val nonce: ByteArray?,
    val recipientPublicKey: ParsedCOSEKey
)

object EncryptionInfoParser {

    fun parse(base64url: String): ParsedEncryptionInfo {
        val bytes = base64UrlDecode(base64url)
        return parse(bytes)
    }

    fun parse(cborBytes: ByteArray): ParsedEncryptionInfo {
        val decoded = CborDecoder(ByteArrayInputStream(cborBytes)).decode()
        val arr = decoded.firstOrNull() as? CborArray
            ?: throw DCAPIError.InvalidEncryptionInfo("Expected CBOR array")

        val items = arr.dataItems
        if (items.size < 2) {
            throw DCAPIError.InvalidEncryptionInfo("Expected at least 2 elements")
        }

        // Format: ["dcapi", {"nonce": bytes, "recipientPublicKey": COSE_Key}]
        val cipherSuiteId = when (val first = items[0]) {
            is UnicodeString -> first.string
            is UnsignedInteger -> first.value.toString()
            else -> "unknown"
        }

        val infoMap = items[1] as? CborMap
            ?: throw DCAPIError.InvalidEncryptionInfo("Second element is not a CBOR map")

        // Extract nonce (optional)
        val nonce = (infoMap[UnicodeString("nonce")] as? ByteString)?.bytes

        // Extract recipientPublicKey
        val rpkItem = infoMap[UnicodeString("recipientPublicKey")]
            ?: throw DCAPIError.InvalidEncryptionInfo("Missing 'recipientPublicKey'")
        val parsedKey = parseCOSEKey(rpkItem as CborMap)

        return ParsedEncryptionInfo(cipherSuiteId, nonce, parsedKey)
    }

    private fun parseCOSEKey(keyMap: CborMap): ParsedCOSEKey {
        // COSE_Key labels: 1=kty, -1=crv, -2=x, -3=y
        val kty = (keyMap[UnsignedInteger(1)] as? UnsignedInteger)?.value?.toInt()
            ?: throw DCAPIError.InvalidEncryptionInfo("Missing kty (label 1)")

        val crv = (keyMap[NegativeInteger(-1)] as? UnsignedInteger)?.value?.toInt()
            ?: throw DCAPIError.InvalidEncryptionInfo("Missing crv (label -1)")

        val x = (keyMap[NegativeInteger(-2)] as? ByteString)?.bytes
            ?: throw DCAPIError.InvalidEncryptionInfo("Missing x coordinate (label -2)")
        if (x.size != 32) throw DCAPIError.InvalidEncryptionInfo("x coordinate must be 32 bytes")

        val y = (keyMap[NegativeInteger(-3)] as? ByteString)?.bytes
            ?: throw DCAPIError.InvalidEncryptionInfo("Missing y coordinate (label -3)")
        if (y.size != 32) throw DCAPIError.InvalidEncryptionInfo("y coordinate must be 32 bytes")

        return ParsedCOSEKey(kty, crv, x, y)
    }

    private fun base64UrlDecode(input: String): ByteArray {
        val padded = when (input.length % 4) {
            2 -> "$input=="
            3 -> "$input="
            else -> input
        }
        val standard = padded.replace('-', '+').replace('_', '/')
        return android.util.Base64.decode(standard, android.util.Base64.DEFAULT)
    }
}
