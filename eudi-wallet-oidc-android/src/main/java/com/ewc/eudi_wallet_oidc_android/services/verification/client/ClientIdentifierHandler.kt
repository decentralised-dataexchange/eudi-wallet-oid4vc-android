package com.ewc.eudi_wallet_oidc_android.services.verification.client

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestException
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestPolicy
import com.ewc.eudi_wallet_oidc_android.services.verification.request.RequestObjectParser
import com.nimbusds.jwt.SignedJWT

/**
 * The processing rules of one client identifier prefix (OpenID4VP 1.0 section 5.9.3).
 *
 * A handler either establishes the verifier's identity and returns it, or throws
 * [PresentationRequestException.ClientNotVerified] saying which rule the request broke.
 */
interface ClientIdentifierHandler {

    /** The prefixes this handler implements. */
    val prefixes: Set<ClientIdPrefix>

    /** False when the wallet should not advertise the prefix under [policy], for example because it lacks the trust material to verify it. */
    fun supported(policy: PresentationRequestPolicy): Boolean = true

    /**
     * @throws PresentationRequestException.ClientNotVerified
     */
    suspend fun verify(
        request: PresentationRequest,
        identifier: ClientIdentifier,
        policy: PresentationRequestPolicy,
    ): VerifierIdentity

    /** The signed request object every authenticating prefix requires. */
    fun signedRequestObject(request: PresentationRequest, prefix: ClientIdPrefix): SignedJWT {
        val jwt = request.request?.takeIf { RequestObjectParser.looksLikeJwt(it) }
            ?: throw PresentationRequestException.ClientNotVerified(
                "the ${prefix.value} prefix requires a signed request object and the request carries none"
            )
        return try {
            SignedJWT.parse(jwt)
        } catch (e: Exception) {
            throw PresentationRequestException.ClientNotVerified("the ${prefix.value} prefix requires a signed request object")
        }
    }
}
