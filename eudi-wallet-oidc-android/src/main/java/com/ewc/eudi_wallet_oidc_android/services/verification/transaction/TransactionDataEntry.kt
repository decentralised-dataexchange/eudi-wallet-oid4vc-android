package com.ewc.eudi_wallet_oidc_android.services.verification.transaction

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.util.Base64

/**
 * One element of the request's `transaction_data` (OpenID4VP 1.0 section 5.1): a base64url
 * encoded JSON object with a `type`, the `credential_ids` that may authorise it, and the type's
 * own parameters.
 *
 * @param raw the string exactly as received; section B.3.3.1 hashes it without decoding.
 * @param hashAlgorithms the `transaction_data_hashes_alg` values, empty when the entry names none.
 * @param json the decoded object, for the host to show the transaction to the user.
 */
data class TransactionDataEntry(
    val raw: String,
    val type: String,
    val credentialIds: List<String>,
    val hashAlgorithms: List<String>,
    val json: JsonObject,
) {
    companion object {

        /** Null when [raw] is not base64url JSON with a `type` and a non-empty `credential_ids`. */
        fun parse(raw: String): TransactionDataEntry? = try {
            val json = JsonParser.parseString(String(Base64.getUrlDecoder().decode(raw.trim().trimEnd('=')), Charsets.UTF_8)).asJsonObject
            val type = json.get("type")?.takeIf { it.isJsonPrimitive }?.asString?.takeIf { it.isNotBlank() }
            val ids = json.get("credential_ids")?.takeIf { it.isJsonArray }?.asJsonArray?.map { it.asString }?.filter { it.isNotBlank() }
            val algorithms = json.get("transaction_data_hashes_alg")?.let { value ->
                when {
                    value.isJsonArray -> value.asJsonArray.map { it.asString }
                    value.isJsonPrimitive -> listOf(value.asString)
                    else -> emptyList()
                }
            }.orEmpty()
            if (type == null || ids.isNullOrEmpty()) null else TransactionDataEntry(raw, type, ids, algorithms, json)
        } catch (e: Exception) {
            null
        }
    }
}

/** The hashes the key binding JWT carries for one query entry, and the algorithm they were made with. */
data class TransactionDataHashes(val algorithm: String, val hashes: List<String>)
