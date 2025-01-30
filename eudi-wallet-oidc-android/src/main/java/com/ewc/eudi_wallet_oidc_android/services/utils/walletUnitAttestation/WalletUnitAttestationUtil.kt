package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation


import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import com.ewc.eudi_wallet_oidc_android.CredentialOfferResponse
import com.ewc.eudi_wallet_oidc_android.NonceResponse
import com.ewc.eudi_wallet_oidc_android.WalletAttestationResult
import com.ewc.eudi_wallet_oidc_android.models.ClientAssertion
import com.ewc.eudi_wallet_oidc_android.services.did.DIDService
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.sdjwt.SDJWTService
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager
import com.google.gson.Gson
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Date
import java.util.UUID
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException


object WalletAttestationUtil {
    val TAG = "WalletUnitAttestation"
    private var baseUrl: String? = null


    suspend fun initiateWalletUnitAttestation(
        context: Context,
        cloudProjectNumber: Long,
        baseUrl: String,
        inputEcKey:ECKey?
    ): WalletAttestationResult? {
        this.baseUrl = baseUrl
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
            clientAssertion = generateClientAssertion(ecKey,did)
            Log.d(TAG, "clientAssertion:$clientAssertion ")


            // Step 7: Process the wallet unit attestation request
            val walletUnitAttestationCredential =
                processWalletUnitAttestationRequest(token, nonce, clientAssertion)


            // Step 8: Log and return both values
            if (walletUnitAttestationCredential != null) {
                Log.d("WalletUnitAttestationCredential", walletUnitAttestationCredential.toString())
            }

            WalletAttestationResult(
                walletUnitAttestationCredential?.credentialOffer,
                clientAssertion,
                did,
                ecKey
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

//    private suspend fun prepareIntegrityTokenProvider(
//        context: Context,
//        cloudProjectNumber: Long
//    ): StandardIntegrityManager.StandardIntegrityTokenProvider =
//        suspendCancellableCoroutine { cont ->
//            val integrityManager = IntegrityManagerFactory.createStandard(context)
//
//            val prepareRequest = StandardIntegrityManager.PrepareIntegrityTokenRequest.builder()
//                .setCloudProjectNumber(cloudProjectNumber)
//                .build()
//
//            integrityManager.prepareIntegrityToken(prepareRequest)
//                .addOnSuccessListener { provider ->
//                    cont.resume(provider)
//                }
//                .addOnFailureListener { exception ->
//                    cont.resumeWithException(exception)
//                }
//        }
//
//
//    private suspend fun requestIntegrityToken(
//        tokenProvider: StandardIntegrityManager.StandardIntegrityTokenProvider,
//        requestHash: String?
//    ): String = suspendCancellableCoroutine { cont ->
//        GlobalScope.launch(Dispatchers.IO) {
//            try {
//
//                // Build the token request
//                val tokenRequest = StandardIntegrityManager.StandardIntegrityTokenRequest.builder()
//                    .setRequestHash(requestHash)
//                    .build()
//
//                // Request the integrity token
//                tokenProvider.request(tokenRequest)
//                    .addOnSuccessListener { response ->
//                        cont.resume(response.token())
//                    }
//                    .addOnFailureListener { exception ->
//                        cont.resumeWithException(exception)
//                    }
//            } catch (e: Exception) {
//                cont.resumeWithException(e)
//            }
//        }
//    }

    private suspend fun processWalletUnitAttestationRequest(
        token: String?,
        nonce: String?,
        clientAssertionValue: String?
    ): CredentialOfferResponse? {

        return withContext(Dispatchers.IO) {
            try {
                val clientAssertion = ClientAssertion(
                    clientAssertion = clientAssertionValue,
                    clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                )

                val response = ApiManager.api.getService()?.sendWUARequest(
                    url = "$baseUrl/wallet-unit/request",
                    deviceIntegrityToken = token ?: "",
                    devicePlatform = "android",
                    nonce = nonce ?: "",
                    body = clientAssertion
                )

                if (response?.isSuccessful == true) {
                    val credentialOfferResponse = response.body()
                    Log.d(TAG, "Request successful: $credentialOfferResponse")
                    return@withContext credentialOfferResponse // Return the response body directly
                } else {
                    Log.e(TAG, "Request failed: ${response?.errorBody()?.string()}")
                    return@withContext null
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error sending request: ${e.message}")
                return@withContext null
            }
        }
    }


     fun generateClientAssertion(
        ecKey: ECKey,
        did: String?
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
                .audience(baseUrl)
                .claim("client_id", did)
                .claim("cnf", mapOf("jwk" to ecKey.toJSONObject()))
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

    private fun getJWKFromKeystore(publicKey: PublicKey): JWK {
        // Generate a unique Key ID (kid) based on the public key
        val keyId = generateKeyId(publicKey)

        // Create an EC JWK from the public key
        val ecJWK = ECKey.Builder(Curve.P_256, publicKey as ECPublicKey?)
            .keyID(keyId)
            .build()

        return ecJWK
    }

    private fun generateKeyId(publicKey: PublicKey): String {
        val keyBytes = publicKey.encoded
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(keyBytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash)
    }

    private suspend fun fetchNonceForDeviceIntegrityToken(url: String): String? {
        return withContext(Dispatchers.IO) {
            try {
                // Make the API call to fetch the nonce
                val response = ApiManager.api.getService()?.fetchNonce(url = url)

                if (response?.isSuccessful == true) {
                    // Parse the response body into the NonceResponse model
                    val responseBody = response.body()?.string()
                    responseBody?.let {
                        val nonceResponse = Gson().fromJson(it, NonceResponse::class.java)
                        Log.d(TAG, "Nonce fetched successfully: ${nonceResponse.nonce}")
                        return@withContext nonceResponse.nonce
                    }
                } else {
                    // Log the error if the response is unsuccessful
                    Log.e(TAG, "Failed to fetch nonce: ${response?.errorBody()?.string()}")
                    return@withContext null
                }
            } catch (e: Exception) {
                // Handle any exceptions that occur during the API call
                Log.e(TAG, "Error fetching nonce: ${e.localizedMessage}")
                return@withContext null
            }
        }
    }


    fun generateWUAProofOfPossession(
        ecKey: ECKey,
        did: String?,
        aud: String?
    ): String? {
        try {
            val now = Date()
            val expirationTime = Date(now.time + 6 * 60 * 1000)

            // Create the JWT claims
            val claimsSet = JWTClaimsSet.Builder()
                .issuer(did)
                .audience(aud)
                .notBeforeTime(now)
                .expirationTime(expirationTime)
                .jwtID("urn:uuid:${UUID.randomUUID().toString()}")
                .build()

            // Create the JWS header
            val header = JWSHeader.Builder(JWSAlgorithm.ES256).build()

            // Sign the JWT
            val signedJWT = SignedJWT(header, claimsSet)

            // Create signer with the private key
            val signer = ECDSASigner(ecKey)

            // Sign the JWT
            signedJWT.sign(signer)

            // Return the serialized JWT
            return signedJWT.serialize()
        }catch (e:Exception){
            Log.d("Error",e.message.toString())
            return null
        }

    }


    fun createKeyBindingJWT(
        aud: String?,
        credential: String,
        subJwk: JWK?,
        claims: Map<String, Any>?
    ): String? {
        try {
            // Start building the JWT claims
            val claimsSetBuilder = JWTClaimsSet.Builder()
                .claim("nonce", UUID.randomUUID().toString())
                .claim("aud", aud)
                .claim("iat", Date())
                .claim("sd_hash", SDJWTService().calculateSHA256Hash(credential))

            // If claims are provided, add them to the claims set
            claims?.forEach { (key, value) ->
                claimsSetBuilder.claim(key, value)
            }

            // Build the claims set
            val claimsSet = claimsSetBuilder.build()
            Log.d("processToken:", "createKeyBindingJWT claimsSet value = ${claimsSet.toJSONObject()}")

            // Create JWT header
            val header = JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType("kb+jwt"))
                .build()

            // Sign the JWT
            val signedJWT = SignedJWT(header, claimsSet)

            // Create signer with the private key
            if (subJwk is ECKey) {
                Log.d("processToken:", "subJwk private key = ${subJwk.toPrivateKey()}")
            }
            else{
                Log.d("processToken:", "subJwk type = ${subJwk?.javaClass?.name}")

            }
            val signer = ECDSASigner(subJwk as ECKey)

            // Sign the JWT
            signedJWT.sign(signer)
            Log.d("processToken:","createKeyBindingJWT signedJWT returned successfully")
            // Return the serialized JWT
            return signedJWT.serialize()


        } catch (e: Exception) {
            Log.d("processToken:", "createKeyBindingJWT signedJWT error ${e.message.toString()}")
            return null
        }
    }
    fun generateHash(input: String): String? {
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            val hashBytes = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
            val hexString = java.lang.StringBuilder()
            for (b in hashBytes) {
                val hex = Integer.toHexString(0xff and b.toInt())
                if (hex.length == 1) hexString.append('0')
                hexString.append(hex)
            }
            hexString.toString()
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("SHA-256 algorithm not found!", e)
        }
    }


    private fun generateES256Key(): KeyPair? {

        val keyPairGenerator = KeyPairGenerator.getInstance("EC")

        keyPairGenerator.initialize(256)

        val keyPair: KeyPair = keyPairGenerator.generateKeyPair()

        return keyPair
    }


//    private fun generateES256Key(): KeyPair? {
//        val keyGenParameterSpecBuilder = KeyGenParameterSpec.Builder(
//            "MyES256Key", // Replace with your unique key alias
//            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
//        )
//            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
//            .setDigests(KeyProperties.DIGEST_SHA256)
//            .setUserAuthenticationRequired(false) // Adjust based on your app's requirements
//
//        try {
//            // Attempt StrongBox-backed key pair generation
//            keyGenParameterSpecBuilder.setIsStrongBoxBacked(true)
//            val keyPairStrongBox = generateKeyPairWithSpec(keyGenParameterSpecBuilder.build())
//            if (keyPairStrongBox != null) return keyPairStrongBox
//        } catch (e: Exception) {
//            e.printStackTrace() // StrongBox not available
//        }
//
//        try {
//            // Attempt TEE-backed key pair generation
//            keyGenParameterSpecBuilder.setIsStrongBoxBacked(false)
//            val keyPairTEE = generateKeyPairWithSpec(keyGenParameterSpecBuilder.build())
//            if (keyPairTEE != null) return keyPairTEE
//        } catch (e: Exception) {
//            e.printStackTrace() // TEE not available
//        }
//
//        // Fallback to software-backed key pair generation
//        return generateSoftwareKeyPair()
//    }
//
//    private fun generateKeyPairWithSpec(spec: KeyGenParameterSpec): KeyPair? {
//        return try {
//            val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
//            keyPairGenerator.initialize(spec)
//            keyPairGenerator.generateKeyPair()
//        } catch (e: Exception) {
//            e.printStackTrace()
//            null
//        }
//    }
//
//    private fun generateSoftwareKeyPair(): KeyPair? {
//        return try {
//            val keyPairGenerator = KeyPairGenerator.getInstance("EC")
//            keyPairGenerator.initialize(ECGenParameterSpec("secp256r1"))
//            keyPairGenerator.generateKeyPair()
//        } catch (e: Exception) {
//            e.printStackTrace()
//            null
//        }
//    }



}



