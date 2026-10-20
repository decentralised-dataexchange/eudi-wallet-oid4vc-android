package com.ewc.eudi_wallet_oidc_android.services.verification.request

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.isValidJWT
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.parseJWTForPayload
import com.ewc.eudi_wallet_oidc_android.services.verification.ClientIdScheme
import com.ewc.eudi_wallet_oidc_android.services.verification.clientIdSchemeHandling.ClientIdParser
import com.google.gson.Gson
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.PlainJWT

/**
 * The RFC 9101 request object: a JWT whose payload is the set of authorization request
 * parameters. Shared by every source that receives one, by value or by reference.
 *
 * Signature verification is not done here. It belongs to the client identifier step, because the
 * key that must have signed the object depends on the client identifier prefix.
 */
internal object RequestObjectParser {

    private val gson = Gson()

    /** True when [data] parses as a compact JWT, signed or `alg: none`. */
    fun looksLikeJwt(data: String?): Boolean = isValidJWT(data)

    /**
     * The request parameters carried in [jwt]. The `request` field is set to the JWT itself when
     * the payload does not carry one, so later steps can reach the original object.
     *
     * @throws PresentationRequestException.Malformed when the JWT or its payload cannot be read.
     */
    fun parse(jwt: String): PresentationRequest {
        val request = try {
            gson.fromJson(parseJWTForPayload(jwt), PresentationRequest::class.java)
        } catch (e: Exception) {
            throw PresentationRequestException.Malformed()
        } ?: throw PresentationRequestException.Malformed()
        request.request = request.request ?: jwt
        return request
    }

    /** True when the request object carries no signature: a plain JWT (`alg: none`). */
    fun isUnsigned(jwt: String): Boolean = try {
        JWTParser.parse(jwt.trim()) is PlainJWT
    } catch (e: Exception) {
        false
    }

    /**
     * OpenID4VP 1.0 section 5.9: a `redirect_uri` request MUST NOT be signed, so an unsigned
     * request object is the normal shape for that prefix and is accepted as it is. For every
     * other prefix the signature is what identifies the verifier, so an unsigned object is
     * refused unless the policy says otherwise.
     *
     * @throws PresentationRequestException.UnsignedRequestObject
     */
    fun requireSignedUnlessRedirectUri(jwt: String, request: PresentationRequest, policy: PresentationRequestPolicy) {
        if (policy.allowUnsignedRequestObjects) return
        if (isUnsigned(jwt) && !isRedirectUriScheme(request)) {
            throw PresentationRequestException.UnsignedRequestObject()
        }
    }

    /**
     * OpenID4VP 1.0 section 5.10.1 and RFC 9101 section 5: when the authorization request URI
     * carries a `client_id`, it MUST be identical to the request object's, prefix included. The
     * check only runs when both are present; the request object is the source of truth for
     * everything else.
     *
     * @throws PresentationRequestException.ClientIdMismatch
     */
    fun requireMatchingClientId(clientIdFromUri: String?, request: PresentationRequest) {
        val fromUri = clientIdFromUri?.takeIf { it.isNotBlank() } ?: return
        val fromObject = request.clientId?.takeIf { it.isNotBlank() } ?: return
        if (fromUri != fromObject) {
            throw PresentationRequestException.ClientIdMismatch(fromUri, fromObject)
        }
    }

    /** True when the client id scheme, explicit or taken from the client_id prefix, is redirect_uri. */
    private fun isRedirectUriScheme(request: PresentationRequest): Boolean {
        val scheme = request.clientIdScheme?.takeIf { it.isNotBlank() }
            ?.let { ClientIdScheme.fromScheme(it) }
            ?: ClientIdParser.getClientIdScheme(request.clientId ?: "")
        return scheme == ClientIdScheme.REDIRECT_URI
    }
}
