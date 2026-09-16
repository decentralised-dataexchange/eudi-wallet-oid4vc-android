package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation


import android.content.Context
import com.ewc.eudi_wallet_oidc_android.BatchCredentialOfferResponse
import com.ewc.eudi_wallet_oidc_android.BatchWalletAttestationResult
import com.ewc.eudi_wallet_oidc_android.BatchWalletUnit
import com.ewc.eudi_wallet_oidc_android.CredentialOfferResponse
import com.ewc.eudi_wallet_oidc_android.clock.WalletClock
import com.ewc.eudi_wallet_oidc_android.NonceResponse
import com.ewc.eudi_wallet_oidc_android.WalletAttestationResult
import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.BatchClientAssertion
import com.ewc.eudi_wallet_oidc_android.models.ClientAssertion
import com.ewc.eudi_wallet_oidc_android.services.did.DIDService
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall
import com.ewc.eudi_wallet_oidc_android.services.utils.generateHash
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager
import com.google.gson.Gson
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.util.Date
import java.util.UUID
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Single home for the Wallet Unit Attestation (WUA) registration flow:
 * key generation, DID creation, Play Integrity, nonce fetch, client assertion,
 * the wallet-unit registration request (single and batch), and the WUA
 * proof-of-possession JWT.
 */
object WalletUnitAttestationService {
    const val TAG = "WalletUnitAttestation"

    private const val CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    private const val PLATFORM = "android"


    suspend fun initiateWalletUnitAttestation(
        context: Context,
        cloudProjectNumber: Long,
        baseUrl: String,
        inputEcKey: ECKey? = null,
        profile: String? = null
    ): WalletAttestationResult? {
        var clientAssertion: String? = null
        return try {
            // Step 1: Generate the key pair with attestation
            val ecKey = inputEcKey ?: generateSoftwareEcKey()
            val did = DIDService().createDID(ecKey)
            Logger.d(TAG, "Generated DID: $did")
            // Step 2: Prepare the integrity token provider
            val tokenProvider = prepareIntegrityTokenProvider(context, cloudProjectNumber)
            Logger.d(TAG, "Integrity token provider ready")

            // Step 3: Fetch the nonce from the server
            val nonce = fetchNonceForDeviceIntegrityToken("$baseUrl/nonce")

            // Step 4: Generate a request hash from the nonce

            val requestHash = nonce?.let { generateHash(it) }

            // Step 5: Request an integrity token
            val token = requestIntegrityToken(tokenProvider, requestHash)
            Logger.d(TAG, "Integrity token received (${token.length} chars)")

            // Step 6: Generate client assertion
            clientAssertion = generateClientAssertion(ecKey, did, audience = baseUrl)
            Logger.d(TAG, "Client assertion generated (${clientAssertion.length} chars)")


            // Step 7: Process the wallet unit attestation request
            val walletUnitAttestationCredential =
                processWalletUnitAttestationRequest(baseUrl, token, nonce, clientAssertion, profile)


            // Step 8: Log and return both values
            if (walletUnitAttestationCredential != null) {
                // The response carries the issued attestation itself — presence only.
                Logger.d(TAG, "Wallet unit attestation received")
            }

            WalletAttestationResult(
                walletUnitAttestationCredential?.credentialOffer,
                walletUnitAttestationCredential?.walletUnitAttestation,
                clientAssertion,
                did,
                ecKey,
                walletUnitAttestationCredential?.credentialIssuer
            )

        } catch (e: Exception) {
            Logger.e(TAG, "Error fetching integrity token: ${e.message}")
            null
        }
    }

    /**
     * Batch registration (#3347): one Play Integrity check, [count] wallet
     * instance attestations. Each client assertion is signed by its own key
     * and carries that key in cnf.jwk; all share one client_id ([clientId],
     * defaulting to the did:key of key 0). The Play Integrity request hash is
     * [BatchRequestHash] over the cnf keys, which the wallet provider
     * recomputes. The result is index-aligned with the keys; each attestation
     * is single use.
     *
     * [firstKey] lets the caller reuse an existing key as key 0 so the wallet
     * unit's DID / client_id stays stable across re-registrations, exactly as
     * [initiateWalletUnitAttestation]'s inputEcKey does. Keys 1..count-1 are
     * always fresh.
     *
     * Returns null only when the flow failed before a request could be made
     * (key generation, Play Integrity, signing). An HTTP error is returned in
     * the result (httpCode / errorBody, no attestations) so the caller can
     * decide to fall back to the single endpoint.
     */
    suspend fun initiateBatchWalletUnitAttestation(
        context: Context,
        cloudProjectNumber: Long,
        baseUrl: String,
        count: Int,
        profile: String? = null,
        clientId: String? = null,
        firstKey: ECKey? = null
    ): BatchWalletAttestationResult? {
        require(count >= 1) { "count must be at least 1" }
        return try {
            val keys = List(count) { i -> if (i == 0 && firstKey != null) firstKey else generateSoftwareEcKey() }
            val dids = keys.map { DIDService().createDID(it) }
            val sharedClientId = clientId ?: dids[0]
            Logger.d(TAG, "Batch registration: $count keys, client_id=$sharedClientId")

            val tokenProvider = prepareIntegrityTokenProvider(context, cloudProjectNumber)
            Logger.d(TAG, "Integrity token provider ready")

            val nonce = fetchWalletProviderNonce("$baseUrl/nonce")?.nonce

            // The batch hash binds the integrity verdict to the cnf keys, not to the nonce.
            val requestHash = BatchRequestHash.compute(keys.map { it.toPublicJWK() })
            val token = requestIntegrityToken(tokenProvider, requestHash)
            Logger.d(TAG, "Integrity token received (${token.length} chars), requestHash=$requestHash")

            val assertions = keys.mapIndexed { i, key ->
                generateClientAssertion(key, dids[i], audience = baseUrl, clientId = sharedClientId)
            }
            if (assertions.any { it.isEmpty() }) {
                Logger.e(TAG, "Batch registration: could not sign every client assertion")
                return null
            }

            val wire = processBatchWalletUnitAttestationRequest(baseUrl, token, nonce, assertions, profile)
            val returned = wire.body?.walletUnitAttestations ?: emptyList()
            if (returned.size != count) {
                Logger.e(
                    TAG,
                    "Batch registration: requested $count attestations, got ${returned.size} (HTTP ${wire.httpCode})"
                )
            } else {
                Logger.d(TAG, "Batch registration: $count attestations received")
            }

            BatchWalletAttestationResult(
                clientId = sharedClientId,
                requestHash = requestHash,
                httpCode = wire.httpCode,
                errorBody = wire.errorBody,
                credentialOffer = wire.body?.credentialOffer,
                credentialIssuer = wire.body?.credentialIssuer,
                units = keys.indices.map { i ->
                    BatchWalletUnit(
                        index = i,
                        did = dids[i],
                        ecKey = keys[i],
                        clientAssertion = assertions[i],
                        walletUnitAttestation = returned.getOrNull(i)
                    )
                }
            )
        } catch (e: Exception) {
            Logger.e(TAG, "Batch registration failed: ${e.message}")
            null
        }
    }

    private suspend fun prepareIntegrityTokenProvider(
        context: Context,
        cloudProjectNumber: Long
    ): StandardIntegrityManager.StandardIntegrityTokenProvider =
        suspendCancellableCoroutine { cont ->
            val integrityManager = IntegrityManagerFactory.createStandard(context)

            val prepareRequest = StandardIntegrityManager.PrepareIntegrityTokenRequest.builder()
                .setCloudProjectNumber(cloudProjectNumber)
                .build()

            integrityManager.prepareIntegrityToken(prepareRequest)
                .addOnSuccessListener { provider ->
                    if (cont.isActive) cont.resume(provider)
                }
                .addOnFailureListener { exception ->
                    if (cont.isActive) cont.resumeWithException(exception)
                }
        }

    private suspend fun requestIntegrityToken(
        tokenProvider: StandardIntegrityManager.StandardIntegrityTokenProvider,
        requestHash: String?
    ): String = suspendCancellableCoroutine { cont ->
        try {
            val tokenRequest = StandardIntegrityManager.StandardIntegrityTokenRequest.builder()
                .setRequestHash(requestHash)
                .build()

            tokenProvider.request(tokenRequest)
                .addOnSuccessListener { response ->
                    if (cont.isActive) cont.resume(response.token())
                }
                .addOnFailureListener { exception ->
                    if (cont.isActive) cont.resumeWithException(exception)
                }
        } catch (e: Exception) {
            if (cont.isActive) cont.resumeWithException(e)
        }
    }

    private suspend fun processWalletUnitAttestationRequest(
        baseUrl: String,
        token: String?,
        nonce: String?,
        clientAssertionValue: String?,
        profile: String? = null
    ): CredentialOfferResponse? = withContext(Dispatchers.IO) {

        val clientAssertion = ClientAssertion(
            clientAssertion = clientAssertionValue,
            clientAssertionType = CLIENT_ASSERTION_TYPE,
            profile = profile
        )

        val result = SafeApiCall.safeApiCallResponse {
            ApiManager.api.getService()?.sendWUARequest(
                url = "$baseUrl/wallet-unit/request",
                deviceIntegrityToken = token ?: "",
                devicePlatform = PLATFORM,
                nonce = nonce ?: "",
                body = clientAssertion
            )
        }

        result.onSuccess { response ->
            if (response.isSuccessful) {
                val credentialOfferResponse = response.body()
                Logger.d(TAG, "Wallet unit request succeeded")
                return@withContext credentialOfferResponse
            } else {
                Logger.e(TAG, "Wallet unit request failed: ${response.code()}")
                return@withContext null
            }
        }.onFailure { e ->
            Logger.e(TAG, "Error sending request: ${e.message}")
            return@withContext null
        }

        return@withContext null // fallback
    }

    private data class BatchWire(
        val httpCode: Int?,
        val body: BatchCredentialOfferResponse?,
        val errorBody: String?
    )

    /** POST {baseUrl}/wallet-unit/request/batch; keeps the HTTP status for the caller. */
    private suspend fun processBatchWalletUnitAttestationRequest(
        baseUrl: String,
        token: String?,
        nonce: String?,
        clientAssertions: List<String>,
        profile: String?
    ): BatchWire = withContext(Dispatchers.IO) {
        val body = BatchClientAssertion(
            clientAssertions = clientAssertions,
            clientAssertionType = CLIENT_ASSERTION_TYPE,
            profile = profile
        )
        val result = SafeApiCall.safeApiCallAnyStatus {
            ApiManager.api.getService()?.sendBatchWUARequest(
                url = "$baseUrl/wallet-unit/request/batch",
                deviceIntegrityToken = token ?: "",
                devicePlatform = PLATFORM,
                nonce = nonce ?: "",
                body = body
            )
        }
        result.fold(
            onSuccess = { response ->
                if (response.isSuccessful) {
                    Logger.d(TAG, "Batch wallet unit request succeeded (${response.code()})")
                    BatchWire(response.code(), response.body(), null)
                } else {
                    val error = try {
                        response.errorBody()?.string()
                    } catch (e: Exception) {
                        null
                    }
                    Logger.e(TAG, "Batch wallet unit request failed: ${response.code()} $error")
                    BatchWire(response.code(), null, error)
                }
            },
            onFailure = { e ->
                Logger.e(TAG, "Error sending batch request: ${e.message}")
                BatchWire(null, null, e.message)
            }
        )
    }


    fun generateClientAssertion(
        ecKey: ECKey,
        did: String?,
        audience: String?,
        clientId: String? = null
    ): String {
        try {
            // iss / sub / client_id are the wallet unit's identity. In a batch every
            // assertion shares one client_id while the kid still names the signing key.
            val subject = clientId ?: did

            Logger.d(TAG, "Client assertion did:$did client_id:$subject")
            val now = Date()
            val expTime = Date(now.time + 3600 * 1000)

            // Create JWT Header
            val header = JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID("$did#${did?.replace("did:key:", "")}")
                .type(JOSEObjectType.JWT)
                .build()
            Logger.d(TAG, "Client assertion header:$header")

            // Create JWT Payload
            val payload = JWTClaimsSet.Builder()
                .audience(audience)
                .claim("client_id", subject)
                .claim("cnf", mapOf("jwk" to ecKey.toPublicJWK().toJSONObject()))
                .expirationTime(expTime)
                .issueTime(now)
                .issuer(subject)
                .subject(subject)
                .jwtID("urn:uuid:${UUID.randomUUID().toString()}")
                .build()
            Logger.d(TAG, "Client assertion payload:$payload")

            // Create the SignedJWT object
            val signedJWT = SignedJWT(header, payload)

            // Sign the JWT with the ECKey's private key
            val signer = ECDSASigner(ecKey)
            signedJWT.sign(signer)

            // Return the serialized token
            return signedJWT.serialize()
        } catch (e: Exception) {
            Logger.e(TAG, "Client assertion error: ${e.message}")
            return ""
        }

    }

    /**
     * GET the wallet provider's nonce document ({service}/nonce or
     * {service}/wallet-provider/nonce): `nonce` binds the Play Integrity
     * token, `c_nonce` is the key-attestation challenge.
     */
    suspend fun fetchWalletProviderNonce(url: String): NonceResponse? = withContext(Dispatchers.IO) {
        val result = SafeApiCall.safeApiCallResponse {
            ApiManager.api.getService()?.fetchNonce(url = url)
        }
        result.fold(
            onSuccess = { response ->
                if (!response.isSuccessful) {
                    Logger.e(TAG, "Failed to fetch nonce: ${response.code()}")
                    return@fold null
                }
                val responseBody = response.body()?.string()
                if (responseBody == null) {
                    Logger.e(TAG, "Nonce response has no body")
                    return@fold null
                }
                try {
                    Gson().fromJson(responseBody, NonceResponse::class.java).also {
                        Logger.d(TAG, "Nonce fetched successfully")
                    }
                } catch (e: Exception) {
                    Logger.e(TAG, "Nonce parse failed: ${e.message}")
                    null
                }
            },
            onFailure = { e ->
                Logger.e(TAG, "Error fetching nonce: ${e.localizedMessage}")
                null
            }
        )
    }

    private suspend fun fetchNonceForDeviceIntegrityToken(url: String): String? =
        fetchWalletProviderNonce(url)?.nonce


    fun generateWUAProofOfPossession(
        ecKey: ECKey,
        did: String?,
        aud: String?
    ): String? {
        try {
            val now = WalletClock.now()
            val issuedAt = WalletClock.issuedAt()
            val expirationTime = Date(now.time + 6 * 60 * 1000)

            // Create the JWT claims
            val claimsSet = JWTClaimsSet.Builder()
                .issuer(did)
                .audience(aud)
                .issueTime(issuedAt)
                .notBeforeTime(issuedAt)
                .expirationTime(expirationTime)
                .jwtID("urn:uuid:${UUID.randomUUID().toString()}")
                .build()

            // Create the JWS header
            val header = JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType("oauth-client-attestation-pop+jwt"))
                .build()

            // Sign the JWT
            val signedJWT = SignedJWT(header, claimsSet)

            // Create signer with the private key
            val signer = ECDSASigner(ecKey)

            // Sign the JWT
            signedJWT.sign(signer)

            // Return the serialized JWT
            return signedJWT.serialize()
        } catch (e: Exception) {
            Logger.e(TAG, "WUA proof-of-possession failed: ${e.message}")
            return null
        }

    }

    /**
     * A plain software P-256 key as a nimbus ECKey (private part included).
     * The private key is never logged, at any level: it is the wallet unit's
     * identity and a single logcat line would hand it to any reader.
     */
    private fun generateSoftwareEcKey(): ECKey {
        val keyPair = generateES256Key()
        val publicKey = keyPair?.public?.let { DIDService().convertToECPublicKey(it) }
        val privateKey = keyPair?.private?.let { DIDService().convertToECPrivateKey(it) }
        return ECKey.Builder(Curve.P_256, publicKey).privateKey(privateKey).build()
    }

    private fun generateES256Key(): KeyPair? {

        val keyPairGenerator = KeyPairGenerator.getInstance("EC")

        keyPairGenerator.initialize(256)

        val keyPair: KeyPair = keyPairGenerator.generateKeyPair()

        return keyPair
    }

}
