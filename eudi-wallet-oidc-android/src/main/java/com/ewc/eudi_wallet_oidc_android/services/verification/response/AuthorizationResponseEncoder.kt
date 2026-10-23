package com.ewc.eudi_wallet_oidc_android.services.verification.response

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.google.gson.Gson
import org.json.JSONObject

/** The form fields a response mode wants: the parameters, a JWE in `response`, or the interactive authorization wrapping. */
class AuthorizationResponseEncoder(private val encrypter: ResponseEncrypter = ResponseEncrypter()) {

    /**
     * @throws SubmissionException
     */
    suspend fun encode(mode: ResponseMode, response: AuthorizationResponse, request: PresentationRequest): Map<String, String> = when (mode) {
        ResponseMode.DirectPost, ResponseMode.DcApi -> response.asFormFields()
        ResponseMode.DirectPostJwt, ResponseMode.DcApiJwt -> mapOf("response" to encrypter.encrypt(response.parameters, request))
        ResponseMode.IarPost -> mapOf(
            "auth_session" to (request.authSession ?: ""),
            "openid4vp_presentation" to Gson().toJson(response.asFormFields()),
        )
        ResponseMode.IarPostJwt -> mapOf(
            "auth_session" to (request.authSession ?: ""),
            "openid4vp_presentation" to JSONObject().put("response", encrypter.encrypt(response.parameters, request)).toString(),
        )
        is ResponseMode.Unsupported -> throw SubmissionException.UnsupportedResponseMode(mode.raw)
    }
}
