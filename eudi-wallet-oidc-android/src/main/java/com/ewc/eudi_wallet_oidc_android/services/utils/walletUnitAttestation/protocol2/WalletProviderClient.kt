package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.protocol2

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.services.did.DIDService
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletUnitAttestationService
import com.google.gson.GsonBuilder
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import java.util.Base64

/**
 * The client of protocol 2 of the wallet provider (CONTRACT.md sections 2 to 4 of the wallet
 * provider iteration 1): every request except the nonce has a JSON body, the statements of the
 * app and the RFC 9421 signature of the request key (the Android Keystore device key).
 *
 * - The WIA request (single and batch) carries the device evidence: a classic Play Integrity token
 *   whose nonce is the request binding, and the device signature over the request binding. The
 *   first request of a wallet unit registers the device key: a new Keystore key with the nonce as
 *   attestation challenge, and its chain in `android_key_attestation_x5c`.
 * - The status read and the revocation code request are signed with the registered key.
 * - An answer with `request_signature_invalid` is sent again once with a new nonce.
 *
 * A wallet provider of protocol 1 ignores the new headers, and answers 404 (no `error_id`) for the
 * status and revocation code routes: [WalletUnitStatusResult.NotSupported].
 *
 * [walletProviderBaseUrl] is `.../organisation/{id}/service/wallet-provider` or the form without
 * `/wallet-provider` (see [walletProviderBase]).
 */
class WalletProviderClient(
    walletProviderBaseUrl: String,
    private val app: WalletAppIdentity,
    private val keys: WalletUnitRequestKeyStore,
    private val integrity: IntegrityTokenSource,
    private val transport: WalletProviderTransport = RetrofitWalletProviderTransport,
    private val clock: () -> Long = { System.currentTimeMillis() / 1000 }
) {

    val baseUrl: String = walletProviderBase(walletProviderBaseUrl)

    /** The answer of a WIA request. The [revocationCode] must be shown once and never stored. */
    data class WiaAnswer(
        val walletUnitAttestation: String?,
        val credentialIssuer: String?,
        val credentialOffer: String?,
        val revocationCode: String?,
        val clientAssertion: String
    )

    data class BatchWiaAnswer(
        val walletUnitAttestations: List<String>,
        val credentialIssuer: String?,
        val credentialOffer: String?,
        val revocationCode: String?,
        val clientAssertions: List<String>
    )

    /** A success with [value], or an [error] (an error answer, or no answer). */
    data class Outcome<T>(val value: T?, val error: WalletProviderError?) {
        val isSuccess: Boolean get() = value != null
    }

    sealed class RevocationCodeResult {
        /** Show the code once (with copy) and never store it. */
        data class Issued(val revocationCode: String) : RevocationCodeResult()

        /** 409 `revocation_code_exists`: the unit has a code already. */
        object AlreadyIssued : RevocationCodeResult()

        /** A wallet provider of protocol 1 (404 with no `error_id`), or no registered request key. */
        object NotSupported : RevocationCodeResult()

        data class Failed(val error: WalletProviderError) : RevocationCodeResult()
    }

    // ---- nonce ----

    /** `GET {base}/nonce`: the member `nonce`, else `c_nonce`. Never signed. */
    suspend fun nonce(): String? {
        val answer = transport.get("$baseUrl/nonce")
        if (!answer.isSuccessful) {
            Logger.e(TAG, "Nonce request failed: ${answer.code ?: answer.failure}")
            return null
        }
        return try {
            val json = JsonParser.parseString(answer.body ?: "").asJsonObject
            json.text("nonce") ?: json.text("c_nonce")
        } catch (e: Exception) {
            Logger.e(TAG, "Nonce answer is not JSON: ${e.message}")
            null
        }
    }

    // ---- WIA ----

    /**
     * `POST {base}/wallet-unit/request` for the cnf key [cnfKey] (private part included: it signs
     * the client assertion). [did] is the client id of the wallet unit.
     */
    suspend fun requestWalletUnitAttestation(
        cnfKey: ECKey,
        did: String,
        profile: String? = null
    ): Outcome<WiaAnswer> {
        var assertion = ""
        val sent = sendWia(
            url = "$baseUrl/wallet-unit/request",
            cnfKeys = listOf(cnfKey)
        ) { x5c ->
            assertion = WalletUnitAttestationService.generateClientAssertion(cnfKey, did, audience = baseUrl)
            if (assertion.isEmpty()) return@sendWia null
            JsonObject().apply {
                addProperty("client_assertion", assertion)
                addProperty("client_assertion_type", CLIENT_ASSERTION_TYPE)
                profile?.let { addProperty("profile", it) }
                x5c?.let { add("android_key_attestation_x5c", GSON.toJsonTree(it)) }
            }
        }
        val json = sent.value ?: return Outcome(null, sent.error)
        return Outcome(
            WiaAnswer(
                walletUnitAttestation = json.text("walletUnitAttestation"),
                credentialIssuer = json.text("credentialIssuer"),
                credentialOffer = json.text("credentialOffer"),
                revocationCode = json.text("revocationCode"),
                clientAssertion = assertion
            ),
            null
        )
    }

    /**
     * `POST {base}/wallet-unit/request/batch`: one WIA for each key of [cnfKeys], with one device
     * evidence for all of them. Every client assertion has the client id [clientId].
     */
    suspend fun requestWalletUnitAttestations(
        cnfKeys: List<ECKey>,
        clientId: String,
        profile: String? = null
    ): Outcome<BatchWiaAnswer> {
        var assertions: List<String> = emptyList()
        val sent = sendWia(
            url = "$baseUrl/wallet-unit/request/batch",
            cnfKeys = cnfKeys
        ) { x5c ->
            assertions = cnfKeys.map { key ->
                WalletUnitAttestationService.generateClientAssertion(
                    key, DIDService().createDID(key), audience = baseUrl, clientId = clientId
                )
            }
            if (assertions.any { it.isEmpty() }) return@sendWia null
            JsonObject().apply {
                add("client_assertions", GSON.toJsonTree(assertions))
                addProperty("client_assertion_type", CLIENT_ASSERTION_TYPE)
                profile?.let { addProperty("profile", it) }
                x5c?.let { add("android_key_attestation_x5c", GSON.toJsonTree(it)) }
            }
        }
        val json = sent.value ?: return Outcome(null, sent.error)
        val wias = json.get("walletUnitAttestations")?.takeIf { it.isJsonArray }?.asJsonArray
            ?.mapNotNull { it.takeIf { e -> e.isJsonPrimitive }?.asString }
            .orEmpty()
        return Outcome(
            BatchWiaAnswer(
                walletUnitAttestations = wias,
                credentialIssuer = json.text("credentialIssuer"),
                credentialOffer = json.text("credentialOffer"),
                revocationCode = json.text("revocationCode"),
                clientAssertions = assertions
            ),
            null
        )
    }

    /**
     * A WIA request: the request key is the registered device key, or a new attested key at the
     * registration ([body] then gets its chain). The evidence binds the nonce and [cnfKeys].
     */
    private suspend fun sendWia(
        url: String,
        cnfKeys: List<JWK>,
        body: (x5c: List<String>?) -> JsonObject?
    ): Outcome<JsonObject> = sendWithRetry(url) { nonce ->
        val registered = keys.registeredKey()
        val attested = if (registered == null) {
            keys.newAttestedKey(nonce.toByteArray(Charsets.UTF_8))
                ?: return@sendWithRetry Prepared.failed("the Keystore refused the device key")
        } else null
        val requestKey = registered ?: attested!!.key
        val prepared = prepare(
            url = url,
            nonce = nonce,
            requestKey = requestKey,
            body = body(attested?.x5c),
            binding = RequestBinding.of(nonce, cnfKeys),
            evidenceRequired = true,
            attested = attested
        )
        if (prepared.failure != null && attested != null) keys.discard(attested)
        prepared
    }

    // ---- status and revocation code ----

    /**
     * `POST {base}/wallet-unit/status`, body `{}`. With [withEvidence] (the last answer said
     * `deviceCheckDue`, or there is no answer yet) the request also carries the device evidence
     * over the request binding of the nonce and no cnf key; without a token it goes without.
     */
    suspend fun status(withEvidence: Boolean): WalletUnitStatusResult {
        if (keys.registeredKey() == null) return WalletUnitStatusResult.NotRegistered
        val url = "$baseUrl/wallet-unit/status"
        var lastAnswer: HttpAnswer? = null
        val sent = sendWithRetry(url, onAnswer = { lastAnswer = it }) { nonce ->
            val requestKey = keys.registeredKey() ?: return@sendWithRetry Prepared.failed("no registered request key")
            prepare(
                url = url,
                nonce = nonce,
                requestKey = requestKey,
                body = JsonObject(),
                binding = if (withEvidence) RequestBinding.of(nonce, emptyList()) else null,
                evidenceRequired = false,
                attested = null
            )
        }
        val answer = lastAnswer
        val code = answer?.code
            ?: return WalletUnitStatusResult.Failed(sent.error ?: WalletProviderError(null))
        val result = WalletUnitStatusResult.fromAnswer(code, answer.body)
        if (result is WalletUnitStatusResult.NotRegistered) keys.forgetRegistered()
        return result
    }

    /** `POST {base}/wallet-unit/revocation-code`, body `{}`: for a unit that has no code yet. */
    suspend fun revocationCode(): RevocationCodeResult {
        if (keys.registeredKey() == null) return RevocationCodeResult.NotSupported
        val url = "$baseUrl/wallet-unit/revocation-code"
        val sent = sendWithRetry(url) { nonce ->
            val requestKey = keys.registeredKey() ?: return@sendWithRetry Prepared.failed("no registered request key")
            prepare(url, nonce, requestKey, JsonObject(), binding = null, evidenceRequired = false, attested = null)
        }
        sent.value?.text("revocationCode")?.let { return RevocationCodeResult.Issued(it) }
        val error = sent.error ?: WalletProviderError(null)
        return when {
            error.errorId == WalletProviderError.REVOCATION_CODE_EXISTS -> RevocationCodeResult.AlreadyIssued
            error.httpCode == 404 && error.errorId == null -> RevocationCodeResult.NotSupported
            else -> RevocationCodeResult.Failed(error)
        }
    }

    // ---- key attestation ----

    /**
     * The protocol 2 headers of a key attestation request to [url] with [body]: the signature
     * with the issuer [cNonce] in `X-Wallet-Unit-Nonce`, and the device evidence over the request
     * binding of the c_nonce and the [attestedKeys]. Null when the unit has no registered request
     * key (the caller then sends the request of protocol 1).
     */
    suspend fun keyAttestationHeaders(
        url: String,
        body: ByteArray,
        cNonce: String,
        attestedKeys: List<JWK>
    ): Map<String, String>? {
        val requestKey = keys.registeredKey() ?: return null
        val binding = RequestBinding.of(cNonce, attestedKeys)
        val headers = Protocol2Headers.signedPost(
            transport.targetUri(url), body, cNonce, app, requestKey, clock()
        ).toMutableMap()
        integrity.token(binding)?.let { headers[Protocol2Headers.INTEGRITY_TOKEN] = it }
        headers[Protocol2Headers.DEVICE_SIGNATURE] = deviceSignature(requestKey, binding)
        return headers
    }

    // ---- the request cycle ----

    private class Prepared(
        val body: ByteArray = ByteArray(0),
        val headers: Map<String, String> = emptyMap(),
        val attested: AttestedRequestKey? = null,
        val failure: String? = null
    ) {
        companion object {
            fun failed(reason: String) = Prepared(failure = reason)
        }
    }

    private suspend fun prepare(
        url: String,
        nonce: String,
        requestKey: WalletUnitRequestKey,
        body: JsonObject?,
        binding: String?,
        evidenceRequired: Boolean,
        attested: AttestedRequestKey?
    ): Prepared {
        body ?: return Prepared.failed("could not make the request body")
        val bytes = GSON.toJson(body).toByteArray(Charsets.UTF_8)
        val headers = Protocol2Headers.signedPost(
            transport.targetUri(url), bytes, nonce, app, requestKey, clock()
        ).toMutableMap()
        if (binding != null) {
            val token = integrity.token(binding)
            if (token == null && evidenceRequired) return Prepared.failed("no Play Integrity token")
            token?.let { headers[Protocol2Headers.INTEGRITY_TOKEN] = it }
            headers[Protocol2Headers.DEVICE_SIGNATURE] = deviceSignature(requestKey, binding)
        }
        return Prepared(bytes, headers, attested)
    }

    /**
     * Gets a nonce, prepares and sends the request; sends it again once with a new nonce when the
     * answer is `request_signature_invalid`. A new attested key becomes the registered key only
     * after a success.
     */
    private suspend fun sendWithRetry(
        url: String,
        onAnswer: (HttpAnswer) -> Unit = {},
        prepare: suspend (nonce: String) -> Prepared
    ): Outcome<JsonObject> {
        var error: WalletProviderError? = null
        for (attempt in 0..1) {
            val nonce = nonce() ?: return Outcome(null, WalletProviderError(null, error = "nonce_unavailable"))
            val prepared = prepare(nonce)
            prepared.failure?.let {
                Logger.e(TAG, "Request to $url not sent: $it")
                return Outcome(null, WalletProviderError(null, error = "request_not_prepared", errorDescription = it))
            }
            val answer = transport.post(url, prepared.headers, prepared.body)
            onAnswer(answer)
            if (answer.isSuccessful) {
                prepared.attested?.let { keys.markRegistered(it) }
                val json = try {
                    JsonParser.parseString(answer.body ?: "{}").takeIf { it.isJsonObject }?.asJsonObject
                } catch (e: Exception) {
                    null
                }
                return json?.let { Outcome(it, null) }
                    ?: Outcome(null, WalletProviderError(answer.code, error = "answer_not_json"))
            }
            prepared.attested?.let { keys.discard(it) }
            error = if (answer.code == null) {
                WalletProviderError(null, error = "no_answer", errorDescription = answer.failure)
            } else {
                WalletProviderError.parse(answer.code, answer.body)
            }
            Logger.e(TAG, "Request to $url refused: HTTP ${answer.code} ${error.errorId ?: error.error}")
            if (error.action != WalletProviderErrorAction.RETRY_WITH_NEW_NONCE) break
        }
        return Outcome(null, error)
    }

    private fun deviceSignature(requestKey: WalletUnitRequestKey, binding: String): String =
        Base64.getUrlEncoder().withoutPadding()
            .encodeToString(requestKey.signDer(binding.toByteArray(Charsets.UTF_8)))

    companion object {
        private const val TAG = "WalletProviderClient"
        const val CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

        private val GSON = GsonBuilder().disableHtmlEscaping().create()

        /**
         * The wallet provider service base `.../service/wallet-provider` from either form that the
         * app resolves (`.../service` from the fallback constants, `.../service/wallet-provider`
         * from the metadata). The protocol 2 routes are only under `/wallet-provider`.
         */
        fun walletProviderBase(resolved: String): String =
            resolved.trim().trimEnd('/').removeSuffix("/wallet-provider") + "/wallet-provider"

        private fun JsonObject.text(name: String): String? =
            get(name)?.takeIf { it.isJsonPrimitive }?.asString
    }
}
