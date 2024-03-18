package com.ewc.eudi_wallet_oidc_android.services.verification

import android.net.Uri
import android.util.Base64
import com.ewc.eudi_wallet_oidc_android.models.DescriptorMap
import com.ewc.eudi_wallet_oidc_android.models.PathNested
import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.PresentationSubmission
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.google.gson.Gson
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.util.Date
import java.util.UUID

class VerificationService : VerificationServiceInterface {

    /**
     * Authorisation requests can be presented to the wallet by verifying in two ways:
     * 1) by value
     * 2) by reference as defined in JWT-Secured Authorization Request (JAR) via use of request_uri.
     *      The custom URL scheme for authorisation requests is openid4vp://.
     *
     * @param data - will accept the full data which is scanned from the QR code or deep link
     *
     * @return PresentationRequest
     */
    override suspend fun processAuthorisationRequest(data: String?): PresentationRequest? {
        if (data.isNullOrBlank())
            return null

        val clientId = Uri.parse(data).getQueryParameter("client_id")
        val state = Uri.parse(data).getQueryParameter("state")
        val redirectUri = Uri.parse(data).getQueryParameter("redirect_uri")
        val nonce = Uri.parse(data).getQueryParameter("nonce")
        val presentationDefinition =
            Uri.parse(data).getQueryParameter("presentation_definition")
        val responseType = Uri.parse(data).getQueryParameter("response_type")
        val scope = Uri.parse(data).getQueryParameter("scope")
        val requestUri = Uri.parse(data).getQueryParameter("request_uri")
        val responseMode = Uri.parse(data).getQueryParameter("response_mode")

        if (presentationDefinition != null) {
            return PresentationRequest(
                clientId = clientId,
                state = state,
                redirectUri = redirectUri,
                nonce = nonce,
                presentationDefinition = presentationDefinition,
                responseMode = responseMode,
                responseType = responseType,
                scope = scope,
                requestUri = requestUri
            )
        } else if (data.startsWith("openid4vp")
            && !requestUri.isNullOrBlank()
        ) {
            val response = ApiManager.api.getService()?.getPresentationDefinitionFromRequestUri(requestUri)
            if (response?.isSuccessful == true) {
                val split = response.body().toString().split(".")[1]

                val jsonString = Base64.decode(
                    split,
                    Base64.URL_SAFE
                ).toString(charset("UTF-8"))

                val json = Gson().fromJson(
                    jsonString,
                    PresentationRequest::class.java
                )

                return json
            } else {
                return null
            }
        } else {
            return null
        }
    }

    /**
     * Authorisation response is sent by constructing the vp_token and presentation_submission values.
     */
    override suspend fun sendVPToken(
        did: String?,
        subJwk: ECKey?,
        presentationRequest: PresentationRequest,
        credentialList: List<String>
    ): String? {
        val iat = Date()
        val jti = "urn:uuid:${UUID.randomUUID()}"
        val claimsSet = JWTClaimsSet.Builder()
            .audience(presentationRequest.clientId)
            .issueTime(iat)
            .expirationTime(Date(iat.time + 600000))
            .issuer(did)
            .jwtID(jti)
            .notBeforeTime(iat)
            .claim("nonce", presentationRequest.nonce)
            .subject(did)
            .claim(
                "vp", com.nimbusds.jose.shaded.json.JSONObject(
                    hashMapOf(
                        "@context" to listOf("https://www.w3.org/2018/credentials/v1"),
                        "holder" to did,
                        "id" to jti,
                        "type" to listOf("VerifiablePresentation"),
                        "verifiableCredential" to credentialList
                    )
                )
            ).build()

        // Create JWT for ES256K alg
        val jwsHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType("JWT"))
            .keyID("$did#${did?.replace("did:key:", "")}")
            .jwk(subJwk?.toPublicJWK())
            .build()

        val jwt = SignedJWT(
            jwsHeader,
            claimsSet
        )

        // Sign with private EC key
        jwt.sign(ECDSASigner(subJwk))

        val response = ApiManager.api.getService()?.sendVPToken(
            presentationRequest.redirectUri ?: "",
            mapOf(
                "vp_token" to jwt.serialize(),
                "presentation_submission" to Gson().toJson(
                    createPresentationSubmission(
                        presentationRequest
                    )
                ),
                "state" to (presentationRequest.state ?: "")
            )
        )

        return if (response?.code() == 302 || response?.code() == 200) {
            response.headers()["Location"] ?: "https://tid-wallet-poc.azurewebsites.net?code=1"
        } else {
            null
        }
    }

    private fun createPresentationSubmission(
        presentationRequest: PresentationRequest
    ): PresentationSubmission? {
        val id = UUID.randomUUID().toString()
        val descriptorMap: ArrayList<DescriptorMap> = ArrayList()

        var presentationDefinition: PresentationDefinition? = null
        if (presentationRequest.presentationDefinition is PresentationDefinition)
            presentationDefinition =
                presentationRequest.presentationDefinition as PresentationDefinition
        else
            presentationDefinition = Gson().fromJson(
                presentationRequest.presentationDefinition as String,
                PresentationDefinition::class.java
            )
        presentationDefinition?.inputDescriptors?.forEachIndexed { index, inputDescriptors ->
            val descriptor = DescriptorMap(
                id = inputDescriptors.id,
                path = "$",
                format = "jwt_vp",
                pathNested = PathNested(
                    id = inputDescriptors.id,
                    format = "jwt_vc",
                    path = "$.verifiableCredential[$index]"
                )
            )
            descriptorMap.add(descriptor)
        }

        val presentationSubmission = PresentationSubmission(
            id = id,
            definitionId = presentationDefinition?.id,
            descriptorMap = descriptorMap
        )
        return presentationSubmission
    }
}