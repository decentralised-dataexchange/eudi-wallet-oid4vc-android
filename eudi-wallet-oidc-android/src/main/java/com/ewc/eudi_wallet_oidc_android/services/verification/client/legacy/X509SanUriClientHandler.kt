package com.ewc.eudi_wallet_oidc_android.services.verification.client.legacy

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.client.ClientIdPrefix
import com.ewc.eudi_wallet_oidc_android.services.verification.client.ClientIdentifier
import com.ewc.eudi_wallet_oidc_android.services.verification.client.ClientIdentifierHandler
import com.ewc.eudi_wallet_oidc_android.services.verification.client.VerifierIdentity
import com.ewc.eudi_wallet_oidc_android.services.verification.client.RequestObjectCertificates
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestException
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestPolicy

/**
 * LEGACY, draft 20 `x509_san_uri`, removed in 1.0: like `x509_san_dns` with a
 * uniformResourceIdentifier SAN instead of a dNSName. Delete with the rest of `legacy/`.
 */
class X509SanUriClientHandler : ClientIdentifierHandler {

    override val prefixes = setOf(ClientIdPrefix.X509_SAN_URI)

    override suspend fun verify(request: PresentationRequest, identifier: ClientIdentifier, policy: PresentationRequestPolicy): VerifierIdentity {
        val jwt = signedRequestObject(request, identifier.prefix)
        val chain = RequestObjectCertificates.chain(jwt)
            ?: throw PresentationRequestException.ClientNotVerified("the request object carries no x5c certificate chain")
        val leaf = chain.first()
        if (!RequestObjectCertificates.verifySignature(jwt, leaf.publicKey)) {
            throw PresentationRequestException.ClientNotVerified("the request object is not signed with the leaf certificate's key")
        }
        if (RequestObjectCertificates.uriNames(leaf).none { it.equals(identifier.identifier, ignoreCase = true) }) {
            throw PresentationRequestException.ClientNotVerified("${identifier.identifier} is not a URI SAN of the leaf certificate")
        }
        val anchored = RequestObjectCertificates.checkChain(chain, policy.trustAnchors)
        return VerifierIdentity(identifier = identifier, verified = true, anchored = anchored, certificateChain = chain)
    }
}
