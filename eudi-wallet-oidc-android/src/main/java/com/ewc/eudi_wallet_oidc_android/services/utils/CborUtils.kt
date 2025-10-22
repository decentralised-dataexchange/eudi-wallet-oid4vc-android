package com.ewc.eudi_wallet_oidc_android.services.utils

import android.util.Base64
import android.util.Log
import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.MajorType
import org.json.JSONObject
import java.io.ByteArrayInputStream
import kotlin.io.encoding.ExperimentalEncodingApi
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString as CborByteString
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.UnicodeString as CborUnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.VpToken
import com.ewc.eudi_wallet_oidc_android.services.verification.PresentationDefinitionProcessor.processPresentationDefinition
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationService
import org.json.JSONArray
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.security.cert.CertificateFactory
import co.nstant.`in`.cbor.model.UnsignedInteger as CBORInteger

class CborUtils {
    companion object {
        @OptIn(ExperimentalEncodingApi::class)
        fun decodeCborCredential(cbor: String?): JSONObject? {
            if (cbor.isNullOrBlank()) {
                return null
            }

            val paddedCbor = padBase64Url(cbor ?: "")

            val cborInBytes = kotlin.io.encoding.Base64.UrlSafe.decode(paddedCbor ?: "")
            return extractCborDataElements(cborInBytes)
        }
        private fun padBase64Url(input: String): String {
            val mod = input.length % 4
            return if (mod == 0) input else input + "=".repeat(4 - mod)
        }
        private fun extractCborDataElements(cborBytes: ByteArray): JSONObject {
            val cbors = CborDecoder(ByteArrayInputStream(cborBytes)).decode()
            var nameSpaces = cbors[0]["nameSpaces"]
            if (nameSpaces==null){
                val documents = cbors[0]["documents"]
                val firstDocument = documents?.get(0)
                val issuerSigned = firstDocument?.get("issuerSigned")
                 nameSpaces = issuerSigned?.get("nameSpaces")
            }

            val jsonObject = JSONObject()
            if (nameSpaces is CborMap) {
                Log.d("TAG", "extractIssuerNamespacedElements: Map")
                nameSpaces.let { map ->
                    // Get all keys from the nameSpaces map
                    val allKeys = map.keys.mapNotNull {
                        (it as? CborUnicodeString)?.string
                    }
                    for (key in allKeys) {
                        // val elements = nameSpaces[key] as CborArray
                        val itemValue = nameSpaces[key]
                        try {
                            when (itemValue) {
                                is CborArray -> {
                                    try {
                                        val newJson = JSONObject()
                                        for (item in itemValue.dataItems) {
                                            val decoded =
                                                CborDecoder(ByteArrayInputStream((item as CborByteString).bytes)).decode()
                                            val identifier =
                                                decoded[0]["elementIdentifier"].toString()
                                            val value = decoded[0]["elementValue"]
                                            if (value?.majorType == MajorType.BYTE_STRING) {
                                                // Convert the ByteString into a readable format, e.g., hex string or Base64
                                                val byteValue = value as CborByteString
                                                val base64String =
                                                    Base64.encodeToString(
                                                        byteValue.bytes,
                                                        Base64.NO_WRAP
                                                    )
                                                newJson.put(identifier, base64String)
                                            } else {
                                                if (identifier == "driving_privileges") {
                                                    Log.d(
                                                        "TAG",
                                                        "extractIssuerNamespacedElements: "
                                                    )
                                                }
                                                // newJson.put(identifier, value.toString())
                                                newJson.put(
                                                    identifier,
                                                    value?.let { convertCborToJson(it) })
                                            }
                                        }
                                        jsonObject.put(key, newJson)
                                    } catch (e: Exception) {
                                        Log.e(
                                            "TAG",
                                            "Error processing CborArray for key '$key': ${e.message}"
                                        )
                                    }
                                }

                                is CborByteString -> {
                                    try {
                                        // Decode the ByteString as CBOR
                                        val decoded =
                                            CborDecoder(ByteArrayInputStream(itemValue.bytes)).decode()
                                        val identifier = decoded[0]["elementIdentifier"].toString()
                                        val value = decoded[0]["elementValue"]
                                        if (value?.majorType == MajorType.BYTE_STRING) {
                                            // Convert the ByteString into a readable format, e.g., hex string or Base64
                                            val byteValue = value as CborByteString
                                            val base64String =
                                                Base64.encodeToString(
                                                    byteValue.bytes,
                                                    Base64.NO_WRAP
                                                )
                                            jsonObject.put(identifier, base64String)
                                        } else {
                                            if (identifier == "driving_privileges") {
                                                Log.d(
                                                    "TAG",
                                                    "extractIssuerNamespacedElements: "
                                                )
                                            }
                                            jsonObject.put(
                                                identifier,
                                                value?.let { convertCborToJson(it) })
                                        }
                                    } catch (e: Exception) {
                                        Log.e(
                                            "TAG",
                                            "Error processing ByteString for key '$key': ${e.message}"
                                        )
                                    }
                                }

                                else -> {
                                    Log.d(
                                        "TAG",
                                        "extractIssuerNamespacedElements: Unsupported type"
                                    )
                                }
                            }
                        } catch (e: Exception) {
                            Log.e("TAG", "Error processing key '$key': ${e.message}")
                            // Handle the error, e.g., log it or skip this key
                        }
                    }
                }
            } else if (nameSpaces is CborArray) {
                Log.d("TAG", "extractIssuerNamespacedElements: Array")
            }
            return jsonObject
        }
        private fun convertCborToJson(value: DataItem): Any {
            return when (value) {
                is CborMap -> {
                    val jsonObject = JSONObject()
                    value.keys.forEach { key ->
                        val keyStr = (key as? CborUnicodeString)?.string ?: key.toString()
                        jsonObject.put(keyStr, convertCborToJson(value[key]!!))
                    }
                    jsonObject
                }
                is CborArray -> {
                    val jsonArray = JSONArray()
                    value.dataItems.forEach { item ->
                        jsonArray.put(convertCborToJson(item))
                    }
                    jsonArray
                }
                is CborUnicodeString -> value.string
                is CBORInteger -> value.value
                is CborByteString -> Base64.encodeToString(value.bytes, Base64.NO_WRAP)
                else -> value.toString()
            }
        }


        @OptIn(ExperimentalEncodingApi::class)
        fun processMdocCredentialToJsonString(allCredentialList: List<String?>?): List<String>? {
            if (allCredentialList.isNullOrEmpty()) {
                return null
            }

            // List to store the converted JSON strings
            val jsonList = mutableListOf<String>()

            for (credential in allCredentialList) {
                if (credential.isNullOrBlank()) {
                    continue
                }

                try {
                    val paddedCbor = padBase64Url(credential ?: "")
                    // Decode each CBOR credential from Base64 URL Safe encoding
                    val cborInBytes = kotlin.io.encoding.Base64.UrlSafe.decode(paddedCbor)

                    // Extract the CBOR data elements and convert them into a JSONObject
                    val jsonObject = parseCborNamespaces(cborInBytes)

                    // Add the JSONObject as a string to the list
                    jsonList.add(jsonObject.toString())
                } catch (e: Exception) {
                    Log.e("TAG", "Error processing credential: ${e.message}")
                }
            }

            return jsonList
        }

        private fun parseCborNamespaces(cborBytes: ByteArray): JSONObject {

            // Recursive helper to convert CBOR DataItem to JSON
            fun cborToJson(value: DataItem?): Any? {
                return when (value) {
                    is CborMap -> {
                        val json = JSONObject()
                        for (keyItem in value.keys) {
                            val key = (keyItem as? CborUnicodeString)?.string ?: keyItem.toString()
                            val v = value[keyItem]
                            json.put(key, cborToJson(v))
                        }
                        json
                    }
                    is CborArray -> {
                        Log.d("TAG", "Nested CBOR Array found, keeping as-is")
                        val array = JSONArray()
                        for (item in value.dataItems) {
                            array.put(cborToJson(item))
                        }
                        array
                    }
                    is CborByteString -> Base64.encodeToString(value.bytes, Base64.NO_WRAP)
                    is CborUnicodeString -> value.string
                    else -> value?.toString()
                }
            }

            val cbors = CborDecoder(ByteArrayInputStream(cborBytes)).decode()
            val nameSpaces = cbors[0]["nameSpaces"]
            val jsonObject = JSONObject()

            if (nameSpaces is CborMap) {
                Log.d("TAG", "extractIssuerNamespacedElements: Map")
                for (keyItem in nameSpaces.keys) {
                    val key = (keyItem as? CborUnicodeString)?.string ?: keyItem.toString()
                    val elements = nameSpaces[keyItem] as? CborArray ?: continue
                    val newJson = JSONObject()

                    for (item in elements.dataItems) {
                        val decoded = CborDecoder(ByteArrayInputStream((item as CborByteString).bytes)).decode()
                        val identifier = decoded[0]["elementIdentifier"].toString()
                        val value = decoded[0]["elementValue"]

                        // Only apply recursion to CBOR maps; other types stay as before
                        if (value is CborMap) {
                            newJson.put(identifier, cborToJson(value))
                        } else if (value?.majorType == MajorType.BYTE_STRING) {
                            val byteValue = value as CborByteString
                            val base64String = Base64.encodeToString(byteValue.bytes, Base64.NO_WRAP)
                            newJson.put(identifier, base64String)
                        } else {
                            newJson.put(identifier, value.toString())
                        }
                    }

                    jsonObject.put(key, newJson)
                }
            } else if (nameSpaces is CborArray) {
                Log.d("TAG", "extractIssuerNamespacedElements: Array")
            }

            return jsonObject
        }



        @OptIn(ExperimentalEncodingApi::class)
        fun processExtractIssuerAuth(allCredentialList: List<String?>?): CborArray {
            var issuerAuthObject = CborArray() // Initialize as empty

            if (allCredentialList != null) {
                for (credential in allCredentialList) {
                    if (credential.isNullOrBlank()) {
                        continue
                    }

                    try {
                        val paddedCbor = padBase64Url(credential ?: "")
                        // Decode each CBOR credential from Base64 URL Safe encoding
                        val cborInBytes = kotlin.io.encoding.Base64.UrlSafe.decode(paddedCbor)
                        // Extract the CBOR data elements and convert them into a JSONObject
                        issuerAuthObject = extractIssuerAuth(cborInBytes)
                    } catch (e: Exception) {
                        Log.e("TAG", "Error processing credential: ${e.message}")
                    }
                }
            }

            return issuerAuthObject
        }


        @OptIn(ExperimentalEncodingApi::class)
        fun extractDocTypeFromIssuerAuth(allCredentialList: List<String?>?): String? {
            var docType: String? = null
            if (allCredentialList != null) {
                for (credential in allCredentialList) {
                    if (credential.isNullOrBlank()) {
                        continue
                    }

                    try {
                        val paddedCbor = padBase64Url(credential ?: "")
                        // Decode each CBOR credential from Base64 URL Safe encoding
                        val cborInBytes = kotlin.io.encoding.Base64.UrlSafe.decode(paddedCbor)
                        val cbors = CborDecoder(ByteArrayInputStream(cborInBytes)).decode()
                        val issuerAuth = cbors[0]["issuerAuth"]
                        println(issuerAuth)
                        docType = issuerAuth?.let { getDocType(it) }


                    } catch (e: Exception) {
                        Log.e("TAG", "Error processing credential: ${e.message}")
                    }
                }
            }

            return docType
        }
        fun getStatusList(cborData: DataItem): Map<String, Any>? {
            val MAX_CHUNK_SIZE = 10_000_000 // 10 MB
            var statusList: Map<String, Any>? = null

            if (cborData is CborArray) {
                for (element in cborData.dataItems) {
                    if (element is CborByteString) {
                        try {
                            val totalSize = element.bytes.size
                            var offset = 0

                            while (offset < totalSize) {
                                val end = (offset + MAX_CHUNK_SIZE).coerceAtMost(totalSize)
                                val chunk = element.bytes.sliceArray(offset until end)
                                offset = end

                                val nestedCBORStream = ByteArrayInputStream(chunk)
                                val decoder = CborDecoder(nestedCBORStream)

                                while (true) {
                                    val nestedCBOR = try { decoder.decodeNext() } catch (e: Exception) { break }

                                    if (nestedCBOR.tag.value == 24L && nestedCBOR is CborByteString) {
                                        try {
                                            val innerTotal = nestedCBOR.bytes.size
                                            var innerOffset = 0

                                            while (innerOffset < innerTotal) {
                                                val innerEnd = (innerOffset + MAX_CHUNK_SIZE).coerceAtMost(innerTotal)
                                                val innerChunk = nestedCBOR.bytes.sliceArray(innerOffset until innerEnd)
                                                innerOffset = innerEnd

                                                val decodedInnerCBORStream = ByteArrayInputStream(innerChunk)
                                                val innerDecoder = CborDecoder(decodedInnerCBORStream)

                                                while (true) {
                                                    val decodedInnerCBOR = try { innerDecoder.decodeNext() } catch (e: Exception) { break }

                                                    statusList = extractStatusList(decodedInnerCBOR ?: continue)
                                                    if (statusList != null) break
                                                }
                                                if (statusList != null) break
                                            }
                                        } catch (e: Exception) {
                                            println("Failed to decode inner ByteString under Tag 24.")
                                        }
                                    }
                                    if (statusList != null) break
                                }
                                if (statusList != null) break
                            }
                        } catch (e: Exception) {
                            println("Could not decode ByteString as CBOR, inspecting data directly.")
                            println("ByteString data: ${element.bytes.joinToString(", ") { it.toString() }}")
                        }
                    } else {
                        println("Element is not a ByteString: $element")
                    }
                    if (statusList != null) break
                }
            }
            return statusList
        }

        private fun getDocType(cborData: DataItem): String? {

            var docType: String? = null
            if (cborData is CborArray) {
                // Iterate over elements in the array
                for (element in cborData.dataItems) { // Using getDataItems() to access the elements
                    // Check if the element is a ByteString
                    if (element is CborByteString) {
                        try {
                            // Decode the ByteString as CBOR
                            val nestedCBORStream = ByteArrayInputStream(element.bytes)
                            // val nestedCBOR = CborDecoder(nestedCBORStream).decode()[0]
                            val nestedCBOR = CborDecoder(nestedCBORStream).decodeNext()
                            if (nestedCBOR.tag.value == 24L) {
                                // Check if the item under the tag is a ByteString
                                if (nestedCBOR is CborByteString) {
                                    try {
                                        // Decode the inner ByteString
                                        val decodedInnerCBORStream =
                                            ByteArrayInputStream(nestedCBOR.bytes)
//                                        val decodedInnerCBOR =
//                                            CborDecoder(decodedInnerCBORStream).decode()[0]
                                        val decodedInnerCBOR = CborDecoder(decodedInnerCBORStream).decodeNext()

                                        // Extract the document type
                                        docType = extractDocType(decodedInnerCBOR ?: continue)
                                        if (docType != null) break
                                    } catch (e: Exception) {
                                        println("Failed to decode inner ByteString under Tag 24.")
                                    }
                                }

                            }

                        } catch (e: Exception) {
                            println("Could not decode ByteString as CBOR, inspecting data directly.")
                            println("ByteString data: ${element.bytes.joinToString(", ") { it.toString() }}")
                        }
                    } else {
                        println("Element is not a ByteString: $element")
                    }
                }
            }

            return docType
        }

        private fun extractDocType(cborData: DataItem): String? {
            // Check if the input is a CborMap
            if (cborData is CborMap) {
                // Get the keys and values from the map
                val keys = cborData.keys
                val values = cborData.values

                // Iterate over the keys and values
                for ((index, key) in keys.withIndex()) {
                    // Check if the key is a CborTextString (UTF-8 string)
                    if (key is CborUnicodeString && key.string == "docType") {
                        // Return the corresponding value if it's a CborTextString
                        val value = values.elementAt(index)
                        if (value is CborUnicodeString) {
                            return value.string
                        } else {
                            println("The value associated with 'docType' is not a string.")
                            return null
                        }
                    }
                }
                println("docType not found in the CBOR map.")
            }
            return null
        }
        private fun extractStatusList(cborData: DataItem): Map<String, Any>? {
            // Check if the input is a CborMap (Map class from the CBOR library)
            if (cborData is CborMap) {
                // Iterate over the keys in the map
                for (key in cborData.getKeys()) {
                    // Check if the key is "status"
                    if (key is CborUnicodeString && key.string == "status") {
                        // Get the value associated with "status"
                        val statusValue = cborData.get(key)

                        // Check if the value is a CborMap
                        if (statusValue is CborMap) {
                            // Now, look for the "status_list" inside the "status" map
                            for (nestedKey in statusValue.getKeys()) {
                                if (nestedKey is CborUnicodeString && nestedKey.string == "status_list") {
                                    // Found "status_list", return it as a map
                                    val statusListValue = statusValue.get(nestedKey)
                                    if (statusListValue is CborMap) {
                                        return cborMapToJsonMap(statusListValue)
                                    } else {
                                        println("The value associated with 'status_list' is not a map.")
                                        return null
                                    }
                                }
                            }
                        }
                    }
                }
            }
            println("'status_list' not found in the CBOR data.")
            return null
        }

        //convert CborMap to a Kotlin Map
        private fun cborMapToJsonMap(cborMap: CborMap): Map<String, Any> {
            val resultMap = mutableMapOf<String, Any>()
            for (key in cborMap.getKeys()) {
                if (key is CborUnicodeString) {
                    resultMap[key.string] = when (val value = cborMap.get(key)) {
                        is CborUnicodeString -> value.string
                        is CBORInteger -> value.value
                        is CborMap -> cborMapToJsonMap(value)
                        is CborByteString -> value.bytes
                        else -> value.toString()
                    }
                }
            }
            return resultMap
        }


        @OptIn(ExperimentalEncodingApi::class)
        fun extractCredentialExpiryFromIssuerAuth(allCredentialList: List<String?>?): String? {
            var expiryUntil: String? = null
            if (allCredentialList != null) {
                for (credential in allCredentialList) {
                    if (credential.isNullOrBlank()) {
                        continue
                    }

                    try {
                        val paddedCbor = padBase64Url(credential ?: "")
                        // Decode each CBOR credential from Base64 URL Safe encoding
                        val cborInBytes = kotlin.io.encoding.Base64.UrlSafe.decode(paddedCbor)
                        val cbors = CborDecoder(ByteArrayInputStream(cborInBytes)).decode()
                        val issuerAuth = cbors[0]["issuerAuth"]
                        println(issuerAuth)
                        expiryUntil = issuerAuth?.let { getCredentialExpiry(it) }


                    } catch (e: Exception) {
                        Log.e("TAG", "Error processing credential: ${e.message}")
                    }
                }
            }

            return expiryUntil
        }
        private fun getCredentialExpiry(cborData: DataItem): String? {

            var expiryUntil: String? = null
            if (cborData is CborArray) {
                // Use iterator instead of dataItems list to avoid huge memory allocation
                val iterator = cborData.dataItems.iterator()

                while (iterator.hasNext()) {
                    val element = iterator.next()

                    if (element is CborByteString) {
                        try {
                            // Decode the ByteString as CBOR
                            val nestedCBORStream = ByteArrayInputStream(element.bytes)
                            val nestedCBORDecoder = CborDecoder(nestedCBORStream)

                            // Decode each nested CBOR item one by one (streaming style)
                            while (true) {
                                val nestedCBOR = try {
                                    nestedCBORDecoder.decodeNext()
                                } catch (e: Exception) {
                                    break
                                }

                                // Handle Tag 24 (CBOR in CBOR)
                                if (nestedCBOR.tag?.value == 24L && nestedCBOR is CborByteString) {

                                    val innerCBORDecoder = CborDecoder(ByteArrayInputStream(nestedCBOR.bytes))

                                    // Decode inner CBOR items one by one
                                    while (true) {
                                        val innerCBOR = try {
                                            innerCBORDecoder.decodeNext()
                                        } catch (e: Exception) {
                                            break
                                        }

                                        // Extract expiry
                                        expiryUntil = extractExpiry(innerCBOR)

                                        // Stop immediately if found
                                        if (expiryUntil != null) break
                                    }
                                }

                                if (expiryUntil != null) break
                            }

                        } catch (e: Exception) {
                            println("Failed to decode ByteString as CBOR: ${e.message}")
                        }
                    } else {
                        println("Element is not a ByteString: $element")
                    }

                    if (expiryUntil != null) break
                }
            }

            return expiryUntil ?: ""
        }

        private fun extractExpiry(cborData: DataItem): String? {
            // Check if the input is a CborMap
            if (cborData is CborMap) {
                // Get the keys and values from the map
                val keys = cborData.keys
                val values = cborData.values

                // Iterate over the keys and values
                for ((index, key) in keys.withIndex()) {
                    // Check if the key is a CborTextString (UTF-8 string)
                    if (key is CborUnicodeString && key.string == "validityInfo") {
                        // Get the validityInfo value
                        val validityInfo = values.elementAt(index)

                        // Check if validityInfo is a CborMap
                        if (validityInfo is CborMap) {
                            // Access the validUntil key
                            val validUntilKey = CborUnicodeString("validUntil")
                            if (validityInfo.keys.contains(validUntilKey)) {
                                val validUntilValue = validityInfo[validUntilKey]

                                // Check if validUntilValue is a CborTextString and return its string representation
                                if (validUntilValue is CborUnicodeString) {
                                    return validUntilValue.string
                                } else {
                                    println("The value associated with 'validUntil' is not a string.")
                                    return null
                                }
                            } else {
                                println("validUntil not found in the validityInfo CBOR map.")
                                return null
                            }
                        } else {
                            println("The value associated with 'validityInfo' is not a CBOR map.")
                            return null
                        }
                    }
                }
                println("validityInfo not found in the CBOR map.")
            }
            return null
        }


        @OptIn(ExperimentalEncodingApi::class)
        fun extractCredentialIssuedAtFromIssuerAuth(credential: String?): String? {
            if (credential.isNullOrBlank()) return null

            return try {
                val paddedCbor = padBase64Url(credential ?: "")
                // Decode the CBOR credential from Base64 URL Safe encoding
                val cborInBytes = kotlin.io.encoding.Base64.UrlSafe.decode(paddedCbor)
                val cbors = CborDecoder(ByteArrayInputStream(cborInBytes)).decode()
                val issuerAuth = cbors[0]["issuerAuth"]
                issuerAuth?.let {  getCredentialIssuedAt(it)}
            } catch (e: Exception) {
                Log.e("TAG", "Error processing credential: ${e.message}")
                null
            }
        }
        private fun getCredentialIssuedAt(cborData: DataItem): String? {
            var issuedAt: String? = null
            val MAX_CHUNK_SIZE = 10_000_000 // 10 MB

            if (cborData is CborArray) {
                for (element in cborData.dataItems) {
                    if (element is CborByteString) {
                        try {
                            val totalSize = element.bytes.size
                            var offset = 0

                            while (offset < totalSize) {
                                val end = (offset + MAX_CHUNK_SIZE).coerceAtMost(totalSize)
                                val chunk = element.bytes.sliceArray(offset until end)
                                offset = end

                                // Stream decode chunk
                                val chunkStream = ByteArrayInputStream(chunk)
                                val decoder = CborDecoder(chunkStream)
                                while (true) {
                                    val nestedCBOR = try {
                                        decoder.decodeNext()
                                    } catch (e: Exception) {
                                        break
                                    }

                                    if (nestedCBOR.tag.value == 24L && nestedCBOR is CborByteString) {
                                        // Inner CBOR streaming
                                        var innerOffset = 0
                                        val innerTotal = nestedCBOR.bytes.size
                                        while (innerOffset < innerTotal) {
                                            val innerEnd = (innerOffset + MAX_CHUNK_SIZE).coerceAtMost(innerTotal)
                                            val innerChunk = nestedCBOR.bytes.sliceArray(innerOffset until innerEnd)
                                            innerOffset = innerEnd

                                            val innerStream = ByteArrayInputStream(innerChunk)
                                            val innerDecoder = CborDecoder(innerStream)
                                            while (true) {
                                                val innerData = try { innerDecoder.decodeNext() } catch (e: Exception) { break }
                                                issuedAt = extractIssuedAt(innerData)
                                            }
                                        }
                                    }
                                }
                            }

                        } catch (e: Exception) {
                            println("Failed to decode ByteString in streaming mode: ${e.message}")
                        }
                    } else {
                        println("Element is not a ByteString: $element")
                    }
                }
            }

            return issuedAt ?: ""
        }

        private fun extractIssuedAt(cborData: DataItem): String? {
            // Check if the input is a CborMap
            if (cborData is CborMap) {
                // Get the keys and values from the map
                val keys = cborData.keys
                val values = cborData.values

                // Iterate over the keys and values
                for ((index, key) in keys.withIndex()) {
                    // Check if the key is a CborTextString (UTF-8 string)
                    if (key is CborUnicodeString && key.string == "validityInfo") {
                        // Get the validityInfo value
                        val validityInfo = values.elementAt(index)

                        // Check if validityInfo is a CborMap
                        if (validityInfo is CborMap) {
                            // Access the validUntil key
                            val validUntilKey = CborUnicodeString("validFrom")
                            if (validityInfo.keys.contains(validUntilKey)) {
                                val validUntilValue = validityInfo[validUntilKey]

                                // Check if validUntilValue is a CborTextString and return its string representation
                                if (validUntilValue is CborUnicodeString) {
                                    return validUntilValue.string
                                } else {
                                    println("The value associated with 'validFrom' is not a string.")
                                    return null
                                }
                            } else {
                                println("validFrom not found in the validityInfo CBOR map.")
                                return null
                            }
                        } else {
                            println("The value associated with 'validityInfo' is not a CBOR map.")
                            return null
                        }
                    }
                }
                println("validityInfo not found in the CBOR map.")
            }
            return null
        }


        @OptIn(ExperimentalEncodingApi::class)
        fun processExtractNameSpaces(
            allCredentialList: List<String?>?,
            presentationRequest: PresentationRequest
        ): CborMap {
            var filteredNameSpaces = CborMap()

            if (allCredentialList != null) {
                for (credential in allCredentialList) {
                    if (credential.isNullOrBlank()) continue
                    // Process the presentation definition
                    val presentationDefinition = if (presentationRequest.dcqlQuery == null) {
                        processPresentationDefinition(presentationRequest.presentationDefinition)
                    } else null

                    try {
                        val paddedCbor = padBase64Url(credential ?: "")
                        // Decode each CBOR credential from Base64 URL Safe encoding
                        val cborInBytes = kotlin.io.encoding.Base64.UrlSafe.decode(paddedCbor)

                        // Extract the full CBOR data elements
                        var nameSpaces = extractNameSpaces(cborInBytes)
                        filteredNameSpaces = nameSpaces
                        println("Extracted nameSpaces: $nameSpaces")
                        // Initialize a list to hold the requested keys
                        val keyList = mutableListOf<String>()
                        // If limitDisclosure is required, filter the nameSpaces
                        if (presentationDefinition !=null){
                            presentationDefinition.inputDescriptors?.forEach { inputDescriptor ->
                                if (inputDescriptor.constraints?.limitDisclosure == "required") {

                                    // Populate the keyList based on the input descriptors
                                    inputDescriptor.constraints?.fields?.forEach { field ->
                                        field.path?.forEach { path ->
                                            val key =
                                                extractKey(path).trim() // Extract the key and trim whitespace

                                            // Check if the key contains a single quote
                                            if (key.contains("'")) {
                                                // Remove the single quote and add to keyList
                                                keyList.add(key.replace("'", ""))
                                            } else {
                                                // Add the key as it is
                                                keyList.add(key)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        else{
                            presentationRequest.dcqlQuery?.let { dcqlQuery ->

                                dcqlQuery.credentials?.forEach { credential ->
                                    credential.claims?.forEach { claim ->
                                        val path = "$['${claim.namespace}']['${claim.claimName}']"
                                        val key = extractKey(path)
                                        keyList.add(key.replace("'", ""))
                                    }
                                }

                            }

                        }
                        if (nameSpaces is CborMap && keyList.isNotEmpty()) {
                            try {
                                Log.d("TAG", "Filtering with DCQL keys: $keyList")

                                nameSpaces.keys.mapNotNull { (it as? CborUnicodeString)?.string }
                                    .forEach { key ->
                                        val elements =
                                            nameSpaces[key] as? CborArray ?: return@forEach
                                        val matchedByteStrings = CborArray()

                                        elements.dataItems.forEach { item ->
                                            try {
                                                val decoded =
                                                    CborDecoder(ByteArrayInputStream((item as CborByteString).bytes)).decode()
                                                val identifier =
                                                    decoded[0]["elementIdentifier"].toString()
                                                        .trim()

                                                if (keyList.contains(identifier)) {
                                                    matchedByteStrings.add(item)
                                                }
                                            } catch (e: Exception) {
                                                Log.e(
                                                    "TAG",
                                                    "Error decoding CBOR item: ${e.message}"
                                                )
                                            }
                                        }

                                        if (matchedByteStrings.dataItems.isNotEmpty()) {
                                            filteredNameSpaces.put(
                                                CborUnicodeString(key),
                                                matchedByteStrings
                                            )
                                        }
                                    }
                            } catch (e: Exception) {
                                Log.e("TAG", "Error filtering nameSpaces: ${e.message}")
                            }
                        }
                    } catch (e: Exception) {
                        Log.e("TAG", "Error processing credential: ${e.message}")
                    }
                }
            }

            return filteredNameSpaces // Return the filtered map containing matched ByteStrings
        }

        private fun extractKey(path: String): String {
            // Remove '[' and ']' characters from the path and split by '.'
            val sanitizedPath = path.replace("[", ".").replace("]", "")
            // Split the sanitized string by '.' and take the last element
            return sanitizedPath.split(".").last()
        }


        private fun extractIssuerAuth(cborBytes: ByteArray): CborArray {
            val cbors = CborDecoder(ByteArrayInputStream(cborBytes)).decode()

            val issuerAuth = cbors[0]["issuerAuth"]
            // val list = cborArrayToList(issuerAuth as CborArray)
            // return list
            return issuerAuth as CborArray
        }


        private fun extractNameSpaces(cborBytes: ByteArray): CborMap {
            val cbors = CborDecoder(ByteArrayInputStream(cborBytes)).decode()

            val nameSpaces = cbors[0]["nameSpaces"]
            //return cborMapToKotlinMap(nameSpaces as CborMap)
            return nameSpaces as CborMap
        }

        private fun cborArrayToList(cborArray: CborArray): List<Any> {
            return cborArray.dataItems.map { convertCborToKotlin(it) }
        }

        private fun convertCborToKotlin(dataItem: DataItem): Any {
            return when (dataItem) {
                is CBORInteger -> dataItem.value
                is CborUnicodeString -> dataItem.string
                is CborByteString -> dataItem.bytes
                is CborArray -> cborArrayToList(dataItem) // Recursive call for nested arrays
                is CborMap -> cborMapToKotlinMap(dataItem) // Convert CborMap to Kotlin Map
                is UnsignedInteger -> dataItem.value
                else -> throw IllegalArgumentException("Unsupported CBOR data type: ${dataItem.javaClass}")
            }
        }

        private fun cborMapToKotlinMap(cborMap: CborMap): Map<Any, Any> {
            return cborMap.keys.associate { key ->
                val kotlinKey = convertCborToKotlin(key)
                val kotlinValue = convertCborToKotlin(cborMap.get(key))
                kotlinKey to kotlinValue
            }
        }


        // Function to encode mDoc (mDL) data into CBOR format
        fun encodeMDocToCbor(mDoc: VpToken): ByteArray {
            val outputStream = ByteArrayOutputStream()
            // Build a CBOR map for the VP Token
            val builder = CborBuilder()
            val mapBuilder = builder.addMap()

            // Add version to the map
            mapBuilder.put("version", mDoc.version)

            // Add an array to the "documents" key
            val arrayBuilder = mapBuilder.putArray("documents")
            for (doc in mDoc.documents) {
                // Create a map for each document
                val docMap = arrayBuilder.addMap()
                    .put("docType", doc.docType)

                // Add issuerSigned information
                val issuerSignedMap = docMap.putMap("issuerSigned")
                //val nameSpacesMap = issuerSignedMap.putMap("nameSpaces")

                issuerSignedMap.put(CborUnicodeString("nameSpaces"), doc.issuerSigned.nameSpaces)

                val issuerAuthArray = issuerSignedMap.putArray("issuerAuth")

                val authList: List<DataItem> = doc.issuerSigned.issuerAuth.getDataItems()

                for (auth in authList) {
                    issuerAuthArray.add(auth)
                }
                issuerAuthArray.end()
                issuerSignedMap.end()
                docMap.end()
            }

            // Add status to the map
            mapBuilder.put("status", mDoc.status.toLong())

            // Finish CBOR encoding
            CborEncoder(outputStream).encode(builder.build())

            // Get CBOR bytes
            val cborBytes = outputStream.toByteArray()

            println("CBOR encoded VP Token: ${cborBytes.contentToString()}")

            return outputStream.toByteArray()
        }
        @OptIn(ExperimentalEncodingApi::class)
        fun extractX5CFromCoseBase64(coseBase64: String): List<String> {
            val paddedCbor = padBase64Url(coseBase64 ?: "")
            val cborInBytes = kotlin.io.encoding.Base64.UrlSafe.decode(paddedCbor ?: "")
            val cbors = CborDecoder(ByteArrayInputStream(cborInBytes)).decode()
            val issuerAuth = cbors[0]["issuerAuth"]
            val coseArray = issuerAuth as? CborArray ?: throw IllegalArgumentException("Expected COSE_Sign1 array")
            if (coseArray.dataItems.size < 4) throw IllegalArgumentException("Invalid COSE_Sign1 structure")
            val unprotectedMap = coseArray.dataItems[1] as? CborMap ?: throw IllegalArgumentException("Unprotected header not a map")
            val x5chainKey = UnsignedInteger(33)
            val x5chainValue = unprotectedMap[x5chainKey]
            Log.d("CBOR", "x5chain (33) value type: ${x5chainValue?.javaClass}, value: $x5chainValue")
            val certList = when (x5chainValue) {
                is CborArray -> x5chainValue
                is CborByteString -> CborArray().apply { add(x5chainValue) }
                is CborUnicodeString -> CborArray().apply { add(x5chainValue) }
                else -> throw IllegalArgumentException("x5chain (33) not found or not a CborArray/ByteString")
            }
            val certFactory = CertificateFactory.getInstance("X.509")
            return certList.dataItems.mapNotNull { item ->
                val certBytes = when (item) {
                    is CborByteString -> item.bytes
                    is CborUnicodeString -> java.util.Base64.getDecoder().decode(item.string)

                    else -> throw IllegalArgumentException("Unsupported certificate format in x5chain: ${item.javaClass}")
                }
                val cert =
                    certFactory.generateCertificate(certBytes.inputStream()) as java.security.cert.X509Certificate
                java.util.Base64.getEncoder().encodeToString(cert.encoded)
            }
        }

    }
}
operator fun DataItem.get(name: String): DataItem? {
    if (this.majorType != MajorType.MAP) return null
    this as CborMap
    return this.get(CborUnicodeString(name))
}

operator fun DataItem.get(index: Int): DataItem? {
    if (this.majorType != MajorType.ARRAY) return null
    this as CborArray
    return this.dataItems.getOrNull(index)
}