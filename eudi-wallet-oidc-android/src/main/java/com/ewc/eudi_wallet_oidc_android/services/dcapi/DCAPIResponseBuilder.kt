package com.ewc.eudi_wallet_oidc_android.services.dcapi

import android.util.Base64
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.UnicodeString
import org.json.JSONObject
import java.io.ByteArrayOutputStream

object DCAPIResponseBuilder {

    /**
     * Builds the encrypted response CBOR and wraps it in the DC API JSON format.
     *
     * Encrypted response CBOR:
     *   ["dcapi", {"enc": <encapsulatedKey bytes>, "cipherText": <cipherText bytes>}]
     *
     * Response JSON:
     *   {"protocol": "org-iso-mdoc", "data": {"response": "<base64url>"}}
     */
    fun buildResponseJSON(encryptionResult: HPKEEncryptionResult): JSONObject {
        val encryptedResponseMap = CborMap().apply {
            put(UnicodeString("enc"), ByteString(encryptionResult.encapsulatedKey))
            put(UnicodeString("cipherText"), ByteString(encryptionResult.cipherText))
        }

        val encryptedResponseCBOR = CborArray().apply {
            add(UnicodeString("dcapi"))
            add(encryptedResponseMap)
        }

        val baos = ByteArrayOutputStream()
        CborEncoder(baos).encode(encryptedResponseCBOR)
        val encryptedResponseBytes = baos.toByteArray()

        val responseBase64 = Base64.encodeToString(
            encryptedResponseBytes,
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
        )

        val dataObj = JSONObject().apply {
            put("response", responseBase64)
        }

        return JSONObject().apply {
            put("protocol", "org-iso-mdoc")
            put("data", dataObj)
        }
    }

    fun buildResponseJSONString(encryptionResult: HPKEEncryptionResult): String {
        return buildResponseJSON(encryptionResult).toString()
    }
}
