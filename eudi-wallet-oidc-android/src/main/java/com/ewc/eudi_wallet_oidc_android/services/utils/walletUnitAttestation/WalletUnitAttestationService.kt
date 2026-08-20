package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation


import android.content.Context
import android.util.Log
import com.ewc.eudi_wallet_oidc_android.CredentialOfferResponse
import com.ewc.eudi_wallet_oidc_android.clock.WalletClock
import com.ewc.eudi_wallet_oidc_android.NonceResponse
import com.ewc.eudi_wallet_oidc_android.WalletAttestationResult
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
 * the wallet-unit registration request, and the WUA proof-of-possession JWT.
 */
object WalletUnitAttestationService {
    const val TAG = "WalletUnitAttestation"


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
            val ecKey = inputEcKey ?: run {
                val keyPair = generateES256Key()
                val publicKey = keyPair?.public?.let { DIDService().convertToECPublicKey(it) }
                val privateKey = keyPair?.private?.let { DIDService().convertToECPrivateKey(it) }
                Log.d(TAG, "Generated privateKey with attestation: $privateKey")
                Log.d(TAG, "Generated publicKey with attestation: $publicKey")

                ECKey.Builder(Curve.P_256, publicKey).privateKey(privateKey).build()
            }
            val did = DIDService().createDID(ecKey)
            Log.d(TAG, "Generated DID: $did")
            // Step 2: Prepare the integrity token provider
            val tokenProvider = prepareIntegrityTokenProvider(context, cloudProjectNumber)
            Log.d(TAG, "Prepare tokenProvider: $tokenProvider")

            // Step 3: Fetch the nonce from the server
            val nonce = fetchNonceForDeviceIntegrityToken("$baseUrl/nonce")
            Log.d(TAG, "Fetched nonce: $nonce")

            // Step 4: Generate a request hash from the nonce

            val requestHash = nonce?.let { generateHash(it) }
            Log.d(TAG, "Generated request hash: $requestHash")

            // Step 5: Request an integrity token
            val token = requestIntegrityToken(tokenProvider, requestHash)
            Log.d(TAG, "integrity token:$token ")

            // Step 6: Generate client assertion
            clientAssertion = generateClientAssertion(ecKey, did, audience = baseUrl)
            Log.d(TAG, "clientAssertion:$clientAssertion ")


            // Step 7: Process the wallet unit attestation request
            val walletUnitAttestationCredential =
                processWalletUnitAttestationRequest(baseUrl, token, nonce, clientAssertion, profile)


            // Step 8: Log and return both values
            if (walletUnitAttestationCredential != null) {
                Log.d("WalletUnitAttestationCredential", walletUnitAttestationCredential.toString())
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
            Log.e(TAG, "Error fetching integrity token: ${e.message}")
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
            clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            profile = profile
        )

        val result = SafeApiCall.safeApiCallResponse {
            ApiManager.api.getService()?.sendWUARequest(
                url = "$baseUrl/wallet-unit/request",
                deviceIntegrityToken = token ?: "",
                devicePlatform = "android",
                nonce = nonce ?: "",
                body = clientAssertion
            )
        }

        result.onSuccess { response ->
            if (response.isSuccessful) {
                val credentialOfferResponse = response.body()
                Log.d(TAG, "Request successful: $credentialOfferResponse")
                return@withContext credentialOfferResponse
            } else {
                Log.e(TAG, "Request failed: ${response.errorBody()?.string()}")
                return@withContext null
            }
        }.onFailure { e ->
            Log.e(TAG, "Error sending request: ${e.message}")
            return@withContext null
        }

        return@withContext null // fallback
    }


    fun generateClientAssertion(
        ecKey: ECKey,
        did: String?,
        audience: String?
    ): String {
        try {

            Log.d(TAG, "Client assertion did:$did")
            val now = Date()
            val expTime = Date(now.time + 3600 * 1000)

            // Create JWT Header
            val header = JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID("$did#${did?.replace("did:key:", "")}")
                .type(JOSEObjectType.JWT)
                .build()
            Log.d(TAG, "Client assertion header:$header")

            // Create JWT Payload
            val payload = JWTClaimsSet.Builder()
                .audience(audience)
                .claim("client_id", did)
                .claim("cnf", mapOf("jwk" to ecKey.toPublicJWK().toJSONObject()))
                .expirationTime(expTime)
                .issueTime(now)
                .issuer(did)
                .subject(did)
                .jwtID("urn:uuid:${UUID.randomUUID().toString()}")
                .build()
            Log.d(TAG, "Client assertion payload:$payload")

            // Create the SignedJWT object
            val signedJWT = SignedJWT(header, payload)

            // Sign the JWT with the ECKey's private key
            val signer = ECDSASigner(ecKey)
            signedJWT.sign(signer)

            // Return the serialized token
            return signedJWT.serialize()
        } catch (e: Exception) {
            Log.d(TAG, "Client assertion error: ${e.message.toString()}")
            println(e.message)
            return ""
        }

    }

    private suspend fun fetchNonceForDeviceIntegrityToken(url: String): String? = withContext(Dispatchers.IO) {

        val result = SafeApiCall.safeApiCallResponse {
            ApiManager.api.getService()?.fetchNonce(url = url)
        }

        result.onSuccess { response ->
            if (response.isSuccessful) {
                val responseBody = response.body()?.string()
                responseBody?.let {
                    val nonceResponse = Gson().fromJson(it, NonceResponse::class.java)
                    Log.d(TAG, "Nonce fetched successfully: ${nonceResponse.nonce}")
                    return@withContext nonceResponse.nonce
                }
            } else {
                Log.e(TAG, "Failed to fetch nonce: ${response.errorBody()?.string()}")
                return@withContext null
            }
        }.onFailure { e ->
            Log.e(TAG, "Error fetching nonce: ${e.localizedMessage}")
            return@withContext null
        }

        return@withContext null // fallback
    }


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
            Log.d("Error", e.message.toString())
            return null
        }

    }

    private fun generateES256Key(): KeyPair? {

        val keyPairGenerator = KeyPairGenerator.getInstance("EC")

        keyPairGenerator.initialize(256)

        val keyPair: KeyPair = keyPairGenerator.generateKeyPair()

        return keyPair
    }

}
