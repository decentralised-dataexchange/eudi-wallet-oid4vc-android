package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation

import android.content.Context
import android.os.Build
import com.ewc.eudi_wallet_oidc_android.BatchWalletAttestationResult
import com.ewc.eudi_wallet_oidc_android.BatchWalletUnit
import com.ewc.eudi_wallet_oidc_android.WalletAttestationResult
import com.ewc.eudi_wallet_oidc_android.clock.WalletClock
import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.WalletProviderOutcome
import com.ewc.eudi_wallet_oidc_android.models.WalletUnitRevocationCodeOutcome
import com.ewc.eudi_wallet_oidc_android.models.WalletUnitStatus
import com.ewc.eudi_wallet_oidc_android.models.WalletUnitStatusOutcome
import com.ewc.eudi_wallet_oidc_android.services.did.DIDService
import com.ewc.eudi_wallet_oidc_android.services.utils.ErrorHandler
import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.Base64
import java.util.concurrent.TimeUnit

/**
 * Talks protocol 2 with the wallet provider: every request except the nonce is
 * signed with the device key of the wallet unit (RFC 9421) and carries device
 * evidence bound to the request (a classic Play Integrity token and a device
 * signature).
 *
 * - The first WIA request of a wallet unit is its **registration**: a new
 *   device key in the Android Keystore with the nonce as its attestation
 *   challenge, and its Key Attestation chain in the body
 *   (`android_key_attestation_x5c`). The answer gives the revocation code once.
 * - Every later request is signed with the same key.
 *
 * The requests of the unit go one at a time (a [Mutex]): a nonce is single
 * use, and a registration must finish before the next request decides whether
 * it registers. Use one client for the whole app.
 *
 * Refusals the SDK can fix are sent again once here: `request_signature_invalid`
 * (a new nonce), `device_registered_before` (send as a registered unit),
 * `request_key_in_use` (a new device key) and, on a WIA request,
 * `device_key_attestation_missing` (register again). Every other refusal comes
 * back in the outcome with `errorId` and `reason`, for the app to act on.
 */
class WalletProviderClient internal constructor(
    baseUrl: String,
    private val appVersion: String,
    private val appBuild: String,
    private val deviceModel: String,
    private val deviceKeys: WalletUnitDeviceKeys,
    private val integrity: WalletUnitIntegrity,
    private val httpClient: OkHttpClient,
    private val clock: () -> Long
) : WalletUnitAttestationProvider {

    /**
     * @param baseUrl the wallet provider address, with or without the final
     *   `/wallet-provider`.
     * @param cloudProjectNumber the Google Cloud project of the Play Integrity tokens.
     * @param appVersion `versionName`, dotted numbers only. The wallet provider
     *   compares it with the minimum version of the app record.
     * @param appBuild `versionCode`; Play Integrity must report the same.
     * @param deviceModel `Build.MANUFACTURER + " " + Build.MODEL`.
     */
    @JvmOverloads
    constructor(
        context: Context,
        baseUrl: String,
        cloudProjectNumber: Long,
        appVersion: String,
        appBuild: String,
        deviceModel: String = "${Build.MANUFACTURER} ${Build.MODEL}",
        httpClient: OkHttpClient = defaultHttpClient()
    ) : this(
        baseUrl = baseUrl,
        appVersion = appVersion,
        appBuild = appBuild,
        deviceModel = deviceModel,
        deviceKeys = KeystoreDeviceKeys(context),
        integrity = ClassicPlayIntegrity(context, cloudProjectNumber),
        httpClient = httpClient,
        clock = { WalletClock.issuedAt().time / 1000 }
    )

    /** `.../organisation/{id}/service/wallet-provider`. */
    override val baseUrl: String = walletProviderBase(baseUrl)

    private val mutex = Mutex()

    /**
     * A device key made for a registration whose answer never came. If the
     * wallet provider registered it after all, the next registration is
     * answered with `device_registered_before`, and this is the key it knows.
     */
    private var unconfirmedKey: DeviceKey? = null

    // MARK: - State

    /** True when the wallet provider registered this unit and its device key is still here. */
    val isRegistered: Boolean
        get() = deviceKeys.registered() != null

    /**
     * True when the unit was registered but its device key is gone (a restored
     * backup, a new phone): the app must start a new wallet unit.
     */
    override val isKeyLost: Boolean
        get() = deviceKeys.hasRegistration && deviceKeys.registered() == null

    /**
     * Forgets the device key: the next WIA request registers a new wallet
     * unit. The app also makes a new client id.
     */
    override suspend fun reset() {
        mutex.withLock {
            deviceKeys.reset()
            unconfirmedKey?.let { deviceKeys.discard(it) }
            unconfirmedKey = null
        }
    }

    // MARK: - WIA

    /**
     * `POST {base}/wallet-unit/request`: one WIA bound to [cnfKey], whose
     * client assertion names the wallet unit by [clientId]. The first request
     * of a unit registers it and gives the revocation code.
     */
    override suspend fun requestWalletUnitAttestation(
        cnfKey: ECKey,
        clientId: String,
        profile: String?
    ): WalletProviderOutcome<WalletAttestationResult> = locked {
        if (isKeyLost) return@locked WalletProviderOutcome.Failed(WalletProviderError.KeyLost.asErrorResponse())
        val did = DIDService().createDID(cnfKey)
        var assertion = ""
        val result = send("/wallet-unit/request", listOf(cnfKey), Evidence.WIA) {
            assertion = WalletUnitAttestationService.generateClientAssertion(
                cnfKey, did, audience = baseUrl, clientId = clientId
            )
            if (assertion.isEmpty()) null else wiaBody(single = assertion, profile = profile)
        }
        when (result) {
            is Sent.Err -> WalletProviderOutcome.Failed(result.error.asErrorResponse())
            is Sent.Ok -> {
                val json = result.answer.json
                val wia = json?.text("walletUnitAttestation")
                val offer = json?.text("credentialOffer")
                if (wia == null && offer == null) {
                    WalletProviderOutcome.Failed(WalletProviderError.UnexpectedAnswer(result.answer.status).asErrorResponse())
                } else {
                    WalletProviderOutcome.Success(
                        WalletAttestationResult(
                            credentialOffer = offer,
                            walletUnitAttestation = wia,
                            clientAssertion = assertion,
                            did = did,
                            ecKey = cnfKey,
                            credentialIssuer = json.text("credentialIssuer"),
                            revocationCode = json.text("revocationCode")
                        )
                    )
                }
            }
        }
    }

    /**
     * `POST {base}/wallet-unit/request/batch`: one WIA for each key of
     * [cnfKeys], one device evidence for all of them. Every client assertion
     * names the wallet unit by [clientId].
     */
    override suspend fun requestWalletUnitAttestations(
        cnfKeys: List<ECKey>,
        clientId: String,
        profile: String?
    ): WalletProviderOutcome<BatchWalletAttestationResult> = locked {
        if (cnfKeys.isEmpty()) {
            return@locked WalletProviderOutcome.Failed(WalletProviderError.BodyNotSerialisable.asErrorResponse())
        }
        if (isKeyLost) return@locked WalletProviderOutcome.Failed(WalletProviderError.KeyLost.asErrorResponse())
        val dids = cnfKeys.map { DIDService().createDID(it) }
        var assertions: List<String> = emptyList()
        val result = send("/wallet-unit/request/batch", cnfKeys, Evidence.WIA) {
            assertions = cnfKeys.mapIndexed { i, key ->
                WalletUnitAttestationService.generateClientAssertion(key, dids[i], audience = baseUrl, clientId = clientId)
            }
            if (assertions.any { it.isEmpty() }) null else wiaBody(batch = assertions, profile = profile)
        }
        when (result) {
            is Sent.Err -> WalletProviderOutcome.Failed(result.error.asErrorResponse())
            is Sent.Ok -> {
                val json = result.answer.json
                    ?: return@locked WalletProviderOutcome.Failed(
                        WalletProviderError.UnexpectedAnswer(result.answer.status).asErrorResponse()
                    )
                val wias = (json.get("walletUnitAttestations") as? JsonArray)
                    ?.mapNotNull { it.takeIf { e -> e.isJsonPrimitive }?.asString }
                    ?: emptyList()
                WalletProviderOutcome.Success(
                    BatchWalletAttestationResult(
                        clientId = clientId,
                        requestHash = null,
                        httpCode = result.answer.status,
                        errorBody = null,
                        credentialOffer = json.text("credentialOffer"),
                        credentialIssuer = json.text("credentialIssuer"),
                        units = cnfKeys.indices.map { i ->
                            BatchWalletUnit(
                                index = i,
                                did = dids[i],
                                ecKey = cnfKeys[i],
                                clientAssertion = assertions.getOrElse(i) { "" },
                                walletUnitAttestation = wias.getOrNull(i)
                            )
                        },
                        revocationCode = json.text("revocationCode")
                    )
                )
            }
        }
    }

    // MARK: - Status and revocation code

    /**
     * `POST {base}/wallet-unit/status`, body `{}`. [withEvidence]: send device
     * evidence, which the wallet provider asks for when the last answer had
     * `deviceCheckDue`, or when there is no answer yet.
     */
    override suspend fun status(withEvidence: Boolean): WalletUnitStatusOutcome = locked {
        if (!deviceKeys.hasRegistration) return@locked WalletUnitStatusOutcome.NotRegistered
        if (deviceKeys.registered() == null) {
            return@locked WalletUnitStatusOutcome.Failed(WalletProviderError.KeyLost.asErrorResponse())
        }
        when (val result = send("/wallet-unit/status", emptyList(), if (withEvidence) Evidence.DEVICE else Evidence.NONE) { JsonObject() }) {
            is Sent.Ok -> WalletUnitStatus.parse(result.answer.body)?.let { WalletUnitStatusOutcome.Known(it) }
                ?: WalletUnitStatusOutcome.Failed(WalletProviderError.UnexpectedAnswer(result.answer.status).asErrorResponse())
            is Sent.Err -> {
                val error = (result.error as? WalletProviderError.Refused)?.error
                when {
                    error == null -> WalletUnitStatusOutcome.Failed(result.error.asErrorResponse())
                    error.errorId == WalletProviderErrorId.UNIT_NOT_FOUND -> {
                        // The wallet provider does not know the device key: the next
                        // WIA request registers the unit again, with a new device key.
                        deviceKeys.reset()
                        WalletUnitStatusOutcome.NotRegistered
                    }
                    error.errorId == WalletProviderErrorId.REVOKED ->
                        WalletUnitStatusOutcome.Known(WalletUnitStatus(WalletUnitStatus.REVOKED, reason = error.reason))
                    error.errorId == WalletProviderErrorId.SUSPENDED ->
                        WalletUnitStatusOutcome.Known(WalletUnitStatus(WalletUnitStatus.SUSPENDED, reason = error.reason))
                    error.errorId == null && error.httpStatus == 404 -> WalletUnitStatusOutcome.NotSupported
                    else -> WalletUnitStatusOutcome.Failed(error)
                }
            }
        }
    }

    /**
     * `POST {base}/wallet-unit/revocation-code`, body `{}`, no device evidence:
     * for a registered unit whose status says `revocationCodeIssued: false`.
     * Call it once.
     */
    override suspend fun revocationCode(): WalletUnitRevocationCodeOutcome = locked {
        if (!deviceKeys.hasRegistration) return@locked WalletUnitRevocationCodeOutcome.NotSupported
        if (deviceKeys.registered() == null) {
            return@locked WalletUnitRevocationCodeOutcome.Failed(WalletProviderError.KeyLost.asErrorResponse())
        }
        when (val result = send("/wallet-unit/revocation-code", emptyList(), Evidence.NONE) { JsonObject() }) {
            is Sent.Ok -> result.answer.json?.text("revocationCode")?.takeIf { it.isNotEmpty() }
                ?.let { WalletUnitRevocationCodeOutcome.Issued(it) }
                ?: WalletUnitRevocationCodeOutcome.Failed(WalletProviderError.UnexpectedAnswer(result.answer.status).asErrorResponse())
            is Sent.Err -> {
                val error = (result.error as? WalletProviderError.Refused)?.error
                when {
                    error == null -> WalletUnitRevocationCodeOutcome.Failed(result.error.asErrorResponse())
                    error.errorId == WalletProviderErrorId.REVOCATION_CODE_EXISTS -> WalletUnitRevocationCodeOutcome.AlreadyIssued
                    error.errorId == null && error.httpStatus == 404 -> WalletUnitRevocationCodeOutcome.NotSupported
                    else -> WalletUnitRevocationCodeOutcome.Failed(error)
                }
            }
        }
    }

    // MARK: - Key attestation

    /**
     * `POST {base}/key-attestation` for a registered unit: signed with the
     * device key, with device evidence over the request binding of the issuer
     * [cNonce] and the [attestedKeys]. [headers] are sent as they are and not
     * signed (the OAuth client attestation of the WIA). No retry with a new
     * nonce: the nonce is the issuer's and cannot be renewed here.
     */
    internal suspend fun keyAttestation(
        body: Any,
        cNonce: String,
        attestedKeys: List<JWK>,
        headers: Map<String, String>
    ): Sent = locked {
        if (deviceKeys.registered() == null) return@locked Sent.Err(WalletProviderError.KeyLost)
        send("/key-attestation", attestedKeys, Evidence.DEVICE, givenNonce = cNonce, extraHeaders = headers) {
            gson.toJsonTree(body) as? JsonObject
        }
    }

    // MARK: - The request cycle

    private suspend fun <T> locked(block: suspend () -> T): T =
        mutex.withLock { withContext(Dispatchers.IO) { block() } }

    internal class Answer(val status: Int, val body: String) {
        val json: JsonObject? by lazy {
            try {
                JsonParser.parseString(body).takeIf { it.isJsonObject }?.asJsonObject
            } catch (e: Exception) {
                null
            }
        }
    }

    internal sealed class Sent {
        class Ok(val answer: Answer) : Sent()
        class Err(val error: WalletProviderError) : Sent()
    }

    private enum class Evidence {
        /** A WIA request: a registration while the unit has none, else device evidence. */
        WIA,

        /** Device evidence of the registered key. */
        DEVICE,

        /** No device evidence (signature only). */
        NONE
    }

    private class Prepared(val request: Request, val madeKey: DeviceKey?)

    /**
     * Gets a nonce (unless [givenNonce]), prepares, signs and sends the
     * request, and handles the refusals the SDK can fix itself.
     */
    private suspend fun send(
        path: String,
        cnfKeys: List<JWK>,
        evidence: Evidence,
        givenNonce: String? = null,
        extraHeaders: Map<String, String> = emptyMap(),
        body: () -> JsonObject?
    ): Sent {
        var retriedWithNewNonce = false
        var handledRegisteredBefore = false
        var replacedDeviceKey = false
        var registeredAgain = false

        while (true) {
            val nonce = givenNonce ?: fetchNonce() ?: return Sent.Err(WalletProviderError.NonceUnavailable)
            val prepared = when (val p = prepare(path, nonce, cnfKeys, evidence, extraHeaders, body)) {
                is Prep.Err -> return Sent.Err(p.error)
                is Prep.Ok -> p.prepared
            }
            val madeKey = prepared.madeKey

            val status: Int
            val text: String
            try {
                httpClient.newCall(prepared.request).execute().use { response ->
                    status = response.code
                    text = response.body?.string() ?: ""
                }
            } catch (e: Exception) {
                // The wallet provider may have registered the key before the answer was lost.
                if (madeKey != null) unconfirmedKey = madeKey
                return Sent.Err(WalletProviderError.Transport(e.message))
            }

            if (status in 200..299) {
                if (madeKey != null) {
                    deviceKeys.markRegistered(madeKey)
                    unconfirmedKey?.takeIf { it !== madeKey }?.let { deviceKeys.discard(it) }
                    unconfirmedKey = null
                }
                return Sent.Ok(Answer(status, text))
            }

            val error = (ErrorHandler.processError(text, status) ?: ErrorResponse())
                .apply { if (httpStatus == null) httpStatus = status }
            val errorId = error.errorId

            if (givenNonce == null && !retriedWithNewNonce && errorId == WalletProviderErrorId.REQUEST_SIGNATURE_INVALID) {
                retriedWithNewNonce = true
                madeKey?.let { deviceKeys.discard(it) }
                continue
            }
            if (madeKey != null && !handledRegisteredBefore && errorId == WalletProviderErrorId.DEVICE_REGISTERED_BEFORE) {
                // Another request registered the unit first: send again as a registered unit.
                handledRegisteredBefore = true
                val known = unconfirmedKey ?: madeKey
                deviceKeys.markRegistered(known)
                if (known !== madeKey) deviceKeys.discard(madeKey)
                unconfirmedKey = null
                continue
            }
            if (madeKey != null && !replacedDeviceKey && errorId == WalletProviderErrorId.REQUEST_KEY_IN_USE) {
                // Another unit has this device key: register with a new one.
                replacedDeviceKey = true
                deviceKeys.discard(madeKey)
                continue
            }
            if (madeKey == null && evidence == Evidence.WIA && !registeredAgain &&
                errorId == WalletProviderErrorId.DEVICE_KEY_ATTESTATION_MISSING
            ) {
                // The wallet provider has no registration for this key (an operator
                // reset it): register again with a new device key and a new nonce.
                registeredAgain = true
                deviceKeys.reset()
                continue
            }
            madeKey?.let { deviceKeys.discard(it) }
            Logger.e(TAG, "refused: HTTP $status ${errorId ?: ""}")
            return Sent.Err(WalletProviderError.Refused(error))
        }
    }

    private sealed class Prep {
        class Ok(val prepared: Prepared) : Prep()
        class Err(val error: WalletProviderError) : Prep()
    }

    private suspend fun prepare(
        path: String,
        nonce: String,
        cnfKeys: List<JWK>,
        evidence: Evidence,
        extraHeaders: Map<String, String>,
        body: () -> JsonObject?
    ): Prep {
        val registeredKey = deviceKeys.registered()
        val registering = evidence == Evidence.WIA && registeredKey == null
        if (registering && deviceKeys.hasRegistration) return Prep.Err(WalletProviderError.KeyLost)
        if (!registering && registeredKey == null) return Prep.Err(WalletProviderError.KeyLost)

        val madeKey = if (registering) {
            try {
                deviceKeys.make(challenge = nonce)
            } catch (e: Exception) {
                return Prep.Err(WalletProviderError.DeviceKey(e))
            }
        } else {
            null
        }
        val key = (madeKey ?: registeredKey)!!
        fun fail(error: WalletProviderError): Prep {
            madeKey?.let { deviceKeys.discard(it) }
            return Prep.Err(error)
        }

        val binding = try {
            BatchRequestHash.requestBinding(nonce, cnfKeys)
        } catch (e: Exception) {
            return fail(WalletProviderError.BodyNotSerialisable)
        }

        var integrityToken: String? = null
        var deviceSignature: String? = null
        if (registering || evidence != Evidence.NONE) {
            integrityToken = try {
                integrity.token(binding)
            } catch (e: Exception) {
                return fail(WalletProviderError.Integrity(e))
            }
            deviceSignature = try {
                Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(key.signing.signDer(binding.toByteArray(Charsets.UTF_8)))
            } catch (e: Exception) {
                return fail(WalletProviderError.DeviceKey(e))
            }
        }

        val bodyObject = body() ?: return fail(WalletProviderError.BodyNotSerialisable)
        if (registering) {
            bodyObject.add(X5C, JsonArray().apply { key.x5c.forEach { add(it) } })
        }
        val bodyBytes = gson.toJson(bodyObject).toByteArray(Charsets.UTF_8)
        val url = baseUrl + path

        val headers = linkedMapOf(
            "Content-Type" to CONTENT_TYPE,
            "Content-Digest" to HTTPMessageSignature.contentDigest(bodyBytes),
            "X-Wallet-Unit-Nonce" to nonce,
            "X-Wallet-Unit-Platform" to PLATFORM,
            "X-Wallet-App-Version" to appVersion,
            "X-Wallet-App-Build" to appBuild,
            "X-Wallet-Device-Model" to deviceModel
        )
        val signed = try {
            HTTPMessageSignature.sign("POST", url, headers, COMPONENTS, clock(), key.signing)
        } catch (e: Exception) {
            null
        } ?: return fail(WalletProviderError.SigningFailed)
        headers["Signature-Input"] = signed.signatureInput
        headers["Signature"] = signed.signature
        integrityToken?.let { headers["X-Wallet-Unit-Integrity-Token"] = it }
        deviceSignature?.let { headers["X-Wallet-Unit-Device-Signature"] = it }
        for ((name, value) in extraHeaders) {
            if (headers.keys.none { it.equals(name, ignoreCase = true) }) headers[name] = value
        }

        val request = try {
            Request.Builder()
                .url(url)
                .post(bodyBytes.toRequestBody(CONTENT_TYPE.toMediaType()))
                .apply { headers.forEach { (name, value) -> header(name, value) } }
                .build()
        } catch (e: Exception) {
            return fail(WalletProviderError.Transport("Invalid wallet provider URL"))
        }
        return Prep.Ok(Prepared(request, madeKey))
    }

    /** `POST {base}/nonce`, unsigned: `c_nonce`, else `nonce`. Null when there is none. */
    private fun fetchNonce(): String? = try {
        val request = Request.Builder().url("$baseUrl/nonce").post(ByteArray(0).toRequestBody(null)).build()
        httpClient.newCall(request).execute().use { response ->
            if (!response.isSuccessful) return null
            val json = JsonParser.parseString(response.body?.string() ?: "").asJsonObject
            (json.text("c_nonce") ?: json.text("nonce"))?.takeIf { it.isNotEmpty() }
        }
    } catch (e: Exception) {
        null
    }

    private fun wiaBody(single: String? = null, batch: List<String>? = null, profile: String?): JsonObject =
        JsonObject().apply {
            single?.let { addProperty("client_assertion", it) }
            batch?.let { all -> add("client_assertions", JsonArray().apply { all.forEach { add(it) } }) }
            addProperty("client_assertion_type", CLIENT_ASSERTION_TYPE)
            if (!profile.isNullOrEmpty()) addProperty("profile", profile)
        }

    companion object {
        private const val TAG = "WalletProviderClient"
        private const val PLATFORM = "android"
        private const val CONTENT_TYPE = "application/json"
        private const val X5C = "android_key_attestation_x5c"
        internal const val CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

        /** The covered components of an Android request, in the order the wallet provider requires. */
        internal val COMPONENTS = listOf(
            "@method", "@target-uri", "content-digest", "x-wallet-unit-nonce",
            "x-wallet-unit-platform", "x-wallet-app-version", "x-wallet-app-build", "x-wallet-device-model"
        )

        /** One serialiser for the exact body bytes: compact, no HTML escaping. */
        private val gson = GsonBuilder().disableHtmlEscaping().create()

        /**
         * `.../service/wallet-provider` from either form the app may hold
         * (`.../service` or `.../service/wallet-provider`).
         */
        internal fun walletProviderBase(url: String): String {
            var base = url.trim().trimEnd('/')
            if (base.endsWith("/wallet-provider")) base = base.removeSuffix("/wallet-provider")
            return "$base/wallet-provider"
        }

        /**
         * The HTTP client of the requests. Pass your own with
         * `retryOnConnectionFailure(false)`: a nonce is single use, and a request
         * sent again by the HTTP client behind the SDK's back can register the
         * unit without the SDK knowing.
         */
        internal fun defaultHttpClient(): OkHttpClient = OkHttpClient.Builder()
            .followRedirects(false)
            .retryOnConnectionFailure(false)
            // Silent unless the host called Logger.configure(...).
            .addInterceptor(Logger.networkInterceptor)
            .connectTimeout(60, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .build()

        private fun JsonObject.text(name: String): String? =
            get(name)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
    }
}
