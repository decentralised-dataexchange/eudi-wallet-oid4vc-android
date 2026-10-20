package com.ewc.eudi_wallet_oidc_android.services.verification.client

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestException
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestPolicy

/**
 * Section 5.9.3 `x509_hash`: the identifier "MUST be a hash and match the hash of the leaf
 * certificate passed with the request. The request MUST be signed with the private key
 * corresponding to the public key in the leaf X.509 certificate ... The value of x509_hash is
 * the base64url-encoded value of the SHA-256 hash of the DER-encoded X.509 certificate. The
 * Wallet MUST validate the signature and the trust chain of the X.509 leaf certificate."
 */
class X509HashClientHandler : ClientIdentifierHandler {

    override val prefixes = setOf(ClientIdPrefix.X509_HASH)

    override suspend fun verify(request: PresentationRequest, identifier: ClientIdentifier, policy: PresentationRequestPolicy): VerifierIdentity {
        val jwt = signedRequestObject(request, identifier.prefix)
        val chain = RequestObjectCertificates.chain(jwt)
            ?: throw PresentationRequestException.ClientNotVerified("the request object carries no x5c certificate chain")
        val leaf = chain.first()

        if (!RequestObjectCertificates.verifySignature(jwt, leaf.publicKey)) {
            throw PresentationRequestException.ClientNotVerified("the request object is not signed with the leaf certificate's key")
        }
        if (RequestObjectCertificates.sha256Base64Url(leaf) != identifier.identifier) {
            throw PresentationRequestException.ClientNotVerified("the client_id hash does not match the leaf certificate")
        }
        val anchored = RequestObjectCertificates.checkChain(chain, policy.trustAnchors)
        return VerifierIdentity(
            identifier = identifier,
            verified = true,
            anchored = anchored,
            certificateChain = chain,
            reason = if (anchored) null else "no trust anchors configured; the chain was checked for consistency only",
        )
    }
}
