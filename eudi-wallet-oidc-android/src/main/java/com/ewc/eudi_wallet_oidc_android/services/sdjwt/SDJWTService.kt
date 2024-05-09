package com.ewc.eudi_wallet_oidc_android.services.sdjwt

import android.util.Base64
import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationService
import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.json.JSONArray
import java.security.MessageDigest
import java.util.Date
import java.util.UUID

class SDJWTService : SDJWTServiceInterface {

    /**
     * Calculates the SHA-256 hash of the input string and returns it in base64url encoding.
     *
     * @param inputString The input string to be hashed.
     * @return The SHA-256 hash of the input string in base64url encoding, or null if the input is null.
     */
    override fun calculateSHA256Hash(inputString: String?): String? {
        if (inputString == null)
            return null

        // Step 1: Convert the text to bytes using UTF-8 encoding
        val decodedBytes = inputString.toByteArray(Charsets.UTF_8)

        // Step 2: Compute the SHA-256 hash
        val sha256Digest = MessageDigest.getInstance("SHA-256").digest(decodedBytes)

        // Step 3: Encode the hash using base64url encoding
        val base64urlEncodedHash = Base64.encodeToString(
            sha256Digest,
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
        )
        return base64urlEncodedHash
    }

    /**
     * Creates a SD-JWT-R using the provided credential, presentation request,
     * and private key.
     *
     * @param credential The credential string containing the disclosures.
     * @param presentationRequest The presentation request containing the presentation definition.
     * @param subJwk The private key used for signing.
     * @return The SD-JWT-R string.
     * @throws IllegalArgumentException if an error occurs during processing or signing.
     */
    override fun createSDJWTR(
        credential: String?,
        presentationRequest: PresentationRequest,
        subJwk: ECKey
    ): String? {
        try {
            val presentationDefinition =
                VerificationService().processPresentationDefinition(presentationRequest.presentationDefinition)
            val processedCredentialWithRequiredDisclosures =
                processDisclosuresWithPresentationDefinition(
                    credential,
                    presentationDefinition
                )
            if (presentationDefinition.format?.containsKey("kb_jwt") == true) {
                val iat = Date()

                val claimsSet = JWTClaimsSet.Builder()
                    .audience(presentationRequest.clientId)
                    .issueTime(iat)
                    .claim("nonce", UUID.randomUUID().toString())
                    .claim(
                        "sd_hash",
                        SDJWTService().calculateSHA256Hash(
                            processedCredentialWithRequiredDisclosures
                        )
                    )
                    .build()

                // Create JWT for ES256K alg
                val jwsHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(JOSEObjectType("kb_jwt"))
                    .build()

                val jwt = SignedJWT(
                    jwsHeader,
                    claimsSet
                )

                // Sign with private EC key
                jwt.sign(ECDSASigner(subJwk))
                return "${processedCredentialWithRequiredDisclosures}~${jwt.serialize()}"
            }

            return processedCredentialWithRequiredDisclosures
        } catch (e: Exception) {
            throw IllegalArgumentException("Error creating SD-JWT-R", e)
        }
    }

    /**
     * Processes disclosures based on the provided credential and presentation definition.
     *
     * @param credential The credential string containing the disclosures.
     * @param presentationDefinition The presentation definition specifying the requested parameters.
     * @return The processed JWT containing only the disclosures matching the requested parameters.
     * @throws IllegalArgumentException if the processing fails due to invalid inputs or other errors.
     */
    override fun processDisclosuresWithPresentationDefinition(
        credential: String?,
        presentationDefinition: PresentationDefinition
    ): String? {
        try {
            // Split the credential into disclosures and the issued JWT

            val disclosures = getDisclosuresFromSDJWT(credential)
            var issuedJwt = getIssuerJwtFromSDJWT(credential)

            // Extract requested parameters from the presentation definition
            val requestedParams: MutableList<String> = mutableListOf()
            presentationDefinition.inputDescriptors?.get(0)?.constraints?.fields?.forEach {
                it.path?.get(0)?.split(".")?.lastOrNull()?.let { paramName ->
                    requestedParams.add(paramName)
                }
            }

            // Filter disclosures based on requested parameters
            disclosures?.forEach { disclosure ->
                val list =
                    JSONArray(Base64.decode(disclosure, Base64.URL_SAFE).toString(charset("UTF-8")))
                if (list.length() >= 2 && requestedParams.contains(list.optString(1))) {
                    issuedJwt = "$issuedJwt~$disclosure"
                }
            }

            return issuedJwt ?: ""
        } catch (e: Exception) {
            throw IllegalArgumentException(
                "Error processing disclosures with presentation definition",
                e
            )
        }
    }

    override fun updateIssuerJwtWithDisclosures(credential: String?): String? {
        val split = credential?.split(".")

        val jsonString = Base64.decode(
            split?.get(1) ?: "",
            Base64.URL_SAFE
        ).toString(charset("UTF-8"))

        val jsonObject = Gson().fromJson(jsonString, JsonObject::class.java)

        val hashList: MutableList<String> = mutableListOf()
        var disclosures = getDisclosuresFromSDJWT(credential)
        disclosures = disclosures?.filter { it != null && it.isNotBlank() }
        disclosures?.forEach { encodedString ->
            try {
                val hash = calculateSHA256Hash(encodedString)
                if (hash != null) {
                    hashList.add(hash)
                }
            } catch (e: IllegalArgumentException) {
            }
        }

        addDisclosuresToCredential(
            jsonObject,
            disclosures ?: listOf(),
            hashList
        )
        return Gson().toJson(jsonObject)
    }

    private fun addDisclosuresToCredential(
        jsonElement: JsonElement,
        disclosures: List<String>,
        hashList: MutableList<String>
    ) {
        if (jsonElement.isJsonObject) {
            val jsonObject = jsonElement.asJsonObject
            if (jsonObject.has("_sd")) {
                val sdList = jsonObject.getAsJsonArray("_sd")

                hashList.forEachIndexed { index, hash ->

                    if (isStringPresentInJSONArray(sdList, hash)) {
                        try {
                            val disclosure = Base64.decode(
                                disclosures[index],
                                Base64.URL_SAFE
                            ).toString(charset("UTF-8"))
                            // Extract key-value pair from the encodedString
                            val (decodedKey, decodedValue) = extractKeyValue(disclosure)
                            // Add key-value pair to jsonObject
                            // Check if decodedValue is an object
                            if (decodedValue is JsonObject) {
                                // If it's an object, add it directly
                                jsonObject.add(decodedKey, decodedValue)
                            } else if (decodedValue is JsonArray) {
                                // If it's an object, add it directly
                                jsonObject.add(decodedKey, decodedValue)
                            } else {
                                // Otherwise, add it as a property
                                jsonObject.addProperty(decodedKey, decodedValue.toString())
                            }
                        } catch (e: IllegalArgumentException) {
                            // Handle invalid base64-encoded strings
                        }
                    }
                }
            }
            jsonObject.entrySet().forEach { (_, value) ->
                addDisclosuresToCredential(value, disclosures, hashList)
            }
        } else if (jsonElement.isJsonArray) {
            jsonElement.asJsonArray.forEach { arrayElement ->
                addDisclosuresToCredential(arrayElement, disclosures, hashList)
            }
        }
    }

    private fun isStringPresentInJSONArray(jsonArray: JsonArray, searchString: String): Boolean {
        for (i in 0 until jsonArray.size()) {
            val element = jsonArray.elementAt(i).asString
            if (element == searchString) {
                return true
            }
        }
        return false
    }

    private fun extractKeyValue(decodedString: String): Pair<String, Any> {
        val jsonArray = JsonParser.parseString(decodedString).asJsonArray
        val key = jsonArray[1].asString
        val value = jsonArray[2]
        return Pair(key, value)
    }

    private fun getDisclosuresFromSDJWT(credential: String?): List<String>? {
        val split = credential?.split("~")
        return if ((split?.size ?: 0) > 1)
            split?.subList(1, split.size)
        else
            listOf()
    }

    private fun getIssuerJwtFromSDJWT(credential: String?): String? {
        val split = credential?.split("~")
        return if ((split?.size ?: 0) > 0)
            split?.first()
        else
            null
    }
}