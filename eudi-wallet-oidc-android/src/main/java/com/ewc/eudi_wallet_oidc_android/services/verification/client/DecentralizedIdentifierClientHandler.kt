package com.ewc.eudi_wallet_oidc_android.services.verification.client

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.SignatureValidator
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestException
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestPolicy
import java.security.SignatureException

/**
 * Section 5.9.3 `decentralized_identifier`: "The request MUST be signed with a private key
 * associated with the DID. A public key to verify the signature MUST be obtained from the
 * verificationMethod property of a DID Document. Since DID Document may include multiple public
 * keys, a particular public key used to sign the request in question MUST be identified by the
 * kid in the JOSE Header."
 *
 * The `kid` has to be a DID URL under the client's own DID. Without that rule anyone could sign
 * with a key from a DID they control and name someone else's DID as the client.
 *
 * The draft `did:` scheme, where the client id is the bare DID, follows the same rules.
 */
class DecentralizedIdentifierClientHandler : ClientIdentifierHandler {

    override val prefixes = setOf(ClientIdPrefix.DECENTRALIZED_IDENTIFIER, ClientIdPrefix.DID)

    override suspend fun verify(request: PresentationRequest, identifier: ClientIdentifier, policy: PresentationRequestPolicy): VerifierIdentity {
        val did = identifier.identifier
        if (!did.startsWith("did:")) {
            throw PresentationRequestException.ClientNotVerified("the client identifier is not a DID")
        }
        val jwt = signedRequestObject(request, identifier.prefix)
        val kid = jwt.header.keyID
            ?: throw PresentationRequestException.ClientNotVerified("the request object names no kid for the verifier's key")
        if (kid != did && !kid.startsWith("$did#") && !kid.startsWith("$did?")) {
            throw PresentationRequestException.ClientNotVerified("the kid does not belong to the client DID")
        }

        val valid = try {
            SignatureValidator().validateSignature(jwt.serialize(), jwksUri = null)
        } catch (e: SignatureException) {
            throw PresentationRequestException.ClientNotVerified(e.message ?: "the request object signature does not verify")
        }
        if (!valid) throw PresentationRequestException.ClientNotVerified("the request object signature does not verify")

        return VerifierIdentity(identifier = identifier, verified = true)
    }
}
