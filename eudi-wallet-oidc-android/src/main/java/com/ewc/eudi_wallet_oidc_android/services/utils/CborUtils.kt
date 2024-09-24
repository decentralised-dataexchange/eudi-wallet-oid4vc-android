package com.ewc.eudi_wallet_oidc_android.services.utils
import android.util.Base64
import android.util.Log
import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.MajorType
import org.json.JSONObject
import java.io.ByteArrayInputStream
import kotlin.io.encoding.ExperimentalEncodingApi
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString as CborByteString
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.UnicodeString as CborUnicodeString
class CborUtils {
    companion object {
        @OptIn(ExperimentalEncodingApi::class)
        fun decodeCborCredential(cbor: String?): JSONObject? {
            if (cbor.isNullOrBlank()) {
                return null
            }
            val cborInBytes = kotlin.io.encoding.Base64.UrlSafe.decode(cbor ?: "")
            return extractCborDataElements(cborInBytes)
        }
        private fun extractCborDataElements(cborBytes: ByteArray): JSONObject {
            val cbors = CborDecoder(ByteArrayInputStream(cborBytes)).decode()
            val nameSpaces = cbors[0]["nameSpaces"]
            val jsonObject = JSONObject()
            if (nameSpaces is CborMap) {
                Log.d("TAG", "extractIssuerNamespacedElements: Map")
                nameSpaces.let { map ->
                    // Get all keys from the nameSpaces map
                    val allKeys = map.keys.mapNotNull {
                        (it as? CborUnicodeString)?.string
                    }
                    for (key in allKeys) {
                        val elements = nameSpaces[key] as CborArray
                        val newJson = JSONObject()
                        for (item in elements.dataItems) {
                            val decoded =
                                CborDecoder(ByteArrayInputStream((item as CborByteString).bytes)).decode()
                            val identifier = decoded[0]["elementIdentifier"].toString()
                            val value = decoded[0]["elementValue"]
                            if (value.majorType == MajorType.BYTE_STRING) {
                                // Convert the ByteString into a readable format, e.g., hex string or Base64
                                val byteValue = value as CborByteString
                                val base64String =
                                    Base64.encodeToString(byteValue.bytes, Base64.NO_WRAP)
                                newJson.put(identifier, base64String)
                            } else {
                                if (identifier == "driving_privileges") {
                                    Log.d("TAG", "extractIssuerNamespacedElements: ")
                                }
                                newJson.put(identifier, value.toString())
                            }
                        }
                        jsonObject.put(key, newJson)
                    }
                }
            } else if (nameSpaces is CborArray) {
                Log.d("TAG", "extractIssuerNamespacedElements: Array")
            }
            return jsonObject
        }
    }
}
operator fun DataItem.get(name: String): DataItem {
    check(this.majorType == MajorType.MAP)
    this as CborMap
    return this.get(CborUnicodeString(name))
}
operator fun DataItem.get(index: Int): DataItem {
    check(this.majorType == MajorType.ARRAY)
    this as CborArray
    return this.dataItems[index]
}