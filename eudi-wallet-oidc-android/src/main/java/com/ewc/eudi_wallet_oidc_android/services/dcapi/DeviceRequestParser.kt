package com.ewc.eudi_wallet_oidc_android.services.dcapi

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.UnicodeString
import java.io.ByteArrayInputStream

data class ParsedDocRequest(
    val docType: String,
    val requestedNamespaces: Map<String, Map<String, Boolean>>,
    val readerAuth: DataItem?
)

data class ParsedDeviceRequest(
    val version: String,
    val docRequests: List<ParsedDocRequest>
)

object DeviceRequestParser {

    fun parse(base64url: String): ParsedDeviceRequest {
        val bytes = base64UrlDecode(base64url)
        return parse(bytes)
    }

    fun parse(cborBytes: ByteArray): ParsedDeviceRequest {
        val decoded = CborDecoder(ByteArrayInputStream(cborBytes)).decode()
        val topMap = decoded.firstOrNull() as? CborMap
            ?: throw DCAPIError.InvalidDeviceRequest("Top-level CBOR is not a map")

        val version = (topMap[UnicodeString("version")] as? UnicodeString)?.string ?: "1.0"

        val docRequestsArray = topMap[UnicodeString("docRequests")] as? CborArray
            ?: throw DCAPIError.InvalidDeviceRequest("Missing or invalid 'docRequests' array")

        val docRequests = mutableListOf<ParsedDocRequest>()
        for (drItem in docRequestsArray.dataItems) {
            val drMap = drItem as? CborMap ?: continue

            val itemsRequestTagged = drMap[UnicodeString("itemsRequest")] as? ByteString
                ?: throw DCAPIError.InvalidDeviceRequest("Missing 'itemsRequest'")

            val innerBytes = itemsRequestTagged.bytes
            val innerDecoded = CborDecoder(ByteArrayInputStream(innerBytes)).decode()
            val irMap = innerDecoded.firstOrNull() as? CborMap
                ?: throw DCAPIError.InvalidDeviceRequest("Failed to decode ItemsRequest CBOR")

            val docType = (irMap[UnicodeString("docType")] as? UnicodeString)?.string
                ?: throw DCAPIError.InvalidDeviceRequest("Missing 'docType' in ItemsRequest")

            val requestedNamespaces = mutableMapOf<String, Map<String, Boolean>>()
            val nsMap = irMap[UnicodeString("nameSpaces")] as? CborMap
            if (nsMap != null) {
                for (nsKey in nsMap.keys) {
                    val namespaceName = (nsKey as? UnicodeString)?.string ?: continue
                    val elemMap = nsMap[nsKey] as? CborMap ?: continue
                    val elements = mutableMapOf<String, Boolean>()
                    for (elemKey in elemMap.keys) {
                        val elemId = (elemKey as? UnicodeString)?.string ?: continue
                        val retain = when (val v = elemMap[elemKey]) {
                            is SimpleValue -> v == SimpleValue.TRUE
                            else -> false
                        }
                        elements[elemId] = retain
                    }
                    requestedNamespaces[namespaceName] = elements
                }
            }

            val readerAuth = drMap[UnicodeString("readerAuth")]

            docRequests.add(ParsedDocRequest(docType, requestedNamespaces, readerAuth))
        }

        return ParsedDeviceRequest(version, docRequests)
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
