package com.ewc.eudi_wallet_oidc_android.services.verification.response

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest

/** The `response_mode` of a request, OpenID4VP 1.0 sections 8.2, 8.3 and Appendix A, plus the EWC interactive authorization modes. */
sealed class ResponseMode(val value: String) {

    object DirectPost : ResponseMode("direct_post")
    object DirectPostJwt : ResponseMode("direct_post.jwt")
    object DcApi : ResponseMode("dc_api")
    object DcApiJwt : ResponseMode("dc_api.jwt")
    object IarPost : ResponseMode("iar-post")
    object IarPostJwt : ResponseMode("iar-post.jwt")
    data class Unsupported(val raw: String) : ResponseMode(raw)

    /** The response travels as a JWE in the `response` parameter (section 8.3). */
    val encrypted: Boolean get() = this is DirectPostJwt || this is DcApiJwt || this is IarPostJwt

    /** The host, not this SDK, carries the response to the verifier. */
    val deliveredByHost: Boolean get() = this is DcApi || this is DcApiJwt

    /** The EWC interactive authorization request: the response is wrapped with the `auth_session`. */
    val interactiveAuthorization: Boolean get() = this is IarPost || this is IarPostJwt

    override fun toString(): String = value

    companion object {
        /** Absent means `direct_post`, as the previous API assumed. */
        fun of(request: PresentationRequest): ResponseMode = parse(request.responseMode)

        fun parse(value: String?): ResponseMode = when (value?.trim()) {
            null, "" -> DirectPost
            DirectPost.value -> DirectPost
            DirectPostJwt.value -> DirectPostJwt
            DcApi.value -> DcApi
            DcApiJwt.value -> DcApiJwt
            IarPost.value -> IarPost
            IarPostJwt.value -> IarPostJwt
            else -> Unsupported(value)
        }
    }
}
