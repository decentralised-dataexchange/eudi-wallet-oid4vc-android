package com.ewc.eudi_wallet_oidc_android.services.verification.transaction

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.PresentationDefinitionProcessor
import java.security.MessageDigest
import java.util.Base64

/**
 * OpenID4VP 1.0 section 8.4 and Appendix B.3.3: reading, validating and hashing the request's
 * `transaction_data`.
 */
object TransactionData {

    const val DEFAULT_ALGORITHM = "sha-256"

    /** IANA Named Information hash names this SDK can compute, in preference order. */
    private val SUPPORTED = linkedMapOf("sha-256" to "SHA-256", "sha-384" to "SHA-384", "sha-512" to "SHA-512")

    /** The raw strings of the request, in order. */
    fun raw(request: PresentationRequest): List<String> = request.transactionDdata.orEmpty()

    /** The entries that parse, skipping the rest: the tolerance of the previous API. */
    fun entriesLenient(request: PresentationRequest): List<TransactionDataEntry> =
        raw(request).mapNotNull { TransactionDataEntry.parse(it) }

    /**
     * Every entry, checked against the request. Section 5.1: "The Wallet MUST return an error if a
     * request contains even one unrecognized transaction data type or transaction data not
     * conforming to the respective type definition." Section 8.5 lists the cases.
     *
     * @param recognisedTypes the types the host can show the user; null accepts any type.
     * @throws InvalidTransactionData
     */
    fun entries(request: PresentationRequest, recognisedTypes: Set<String>? = null): List<TransactionDataEntry> {
        val raw = raw(request)
        if (raw.isEmpty()) return emptyList()
        val queryIds = queryEntryIds(request)
        val unbound = request.dcqlQuery?.credentials.orEmpty()
            .filter { !it.requireCryptographicHolderBinding }.mapNotNull { it.id }.toSet()

        return raw.mapIndexed { index, value ->
            val entry = TransactionDataEntry.parse(value)
                ?: throw InvalidTransactionData("transaction_data[$index] is not a base64url JSON object with type and credential_ids")
            if (recognisedTypes != null && entry.type !in recognisedTypes) {
                throw InvalidTransactionData("the transaction data type ${entry.type} is not supported")
            }
            entry.credentialIds.firstOrNull { it !in queryIds }?.let {
                throw InvalidTransactionData("transaction_data[$index] names $it, which the query does not request")
            }
            // B.3.3: "Wallets MUST reject requests with transaction data types that have the
            // require_cryptographic_holder_binding parameter set to false."
            entry.credentialIds.firstOrNull { it in unbound }?.let {
                throw InvalidTransactionData("transaction_data[$index] names $it, which is requested without holder binding")
            }
            if (entry.hashAlgorithms.isNotEmpty() && entry.hashAlgorithms.none { it in SUPPORTED }) {
                throw InvalidTransactionData("none of the hash algorithms ${entry.hashAlgorithms} is supported")
            }
            entry
        }
    }

    /**
     * B.3.3.1: one hash per entry that names [entryId], in request order, made over the string as
     * received. The algorithm is the first supported one every such entry allows; an entry that
     * names none allows only `sha-256`. Null when no entry names [entryId].
     *
     * @throws InvalidTransactionData when the entries allow no algorithm in common
     */
    fun hashes(entries: List<TransactionDataEntry>, entryId: String): TransactionDataHashes? {
        val naming = entries.filter { entryId in it.credentialIds }
        if (naming.isEmpty()) return null
        val algorithm = SUPPORTED.keys.firstOrNull { name ->
            naming.all { entry -> if (entry.hashAlgorithms.isEmpty()) name == DEFAULT_ALGORITHM else name in entry.hashAlgorithms }
        } ?: throw InvalidTransactionData("the transaction data for $entryId allow no common hash algorithm")
        return TransactionDataHashes(algorithm, naming.map { hash(it.raw, algorithm) })
    }

    /** The hashes for every query entry the transaction data names. */
    fun hashesByEntry(entries: List<TransactionDataEntry>): Map<String, TransactionDataHashes> =
        entries.flatMap { it.credentialIds }.distinct().mapNotNull { id -> hashes(entries, id)?.let { id to it } }.toMap()

    /** The previous API's tolerance: entries that parse, and an entry id whose entries share no algorithm gets none. */
    fun hashesByEntryLenient(request: PresentationRequest): Map<String, TransactionDataHashes> {
        val entries = entriesLenient(request)
        return entries.flatMap { it.credentialIds }.distinct().mapNotNull { id ->
            try { hashes(entries, id)?.let { id to it } } catch (e: InvalidTransactionData) { null }
        }.toMap()
    }

    fun hash(raw: String, algorithm: String = DEFAULT_ALGORITHM): String {
        val digest = MessageDigest.getInstance(SUPPORTED[algorithm] ?: throw InvalidTransactionData("unsupported hash algorithm $algorithm"))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest.digest(raw.toByteArray(Charsets.UTF_8)))
    }

    private fun queryEntryIds(request: PresentationRequest): Set<String> {
        request.dcqlQuery?.credentials?.let { return it.mapNotNull { q -> q.id }.toSet() }
        return request.presentationDefinition?.let {
            PresentationDefinitionProcessor.processPresentationDefinition(it).inputDescriptors.orEmpty().mapNotNull { d -> d.id }.toSet()
        }.orEmpty()
    }

    /** Section 8.5 `invalid_transaction_data`. */
    class InvalidTransactionData(detail: String) : Exception(detail) {
        val oauthError: String = "invalid_transaction_data"
    }
}
