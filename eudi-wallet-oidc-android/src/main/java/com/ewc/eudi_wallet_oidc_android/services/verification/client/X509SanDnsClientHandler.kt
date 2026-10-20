package com.ewc.eudi_wallet_oidc_android.services.verification.client

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestException
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestPolicy
import java.net.URI

/**
 * Section 5.9.3 `x509_san_dns`: the identifier "MUST be a DNS name and match a dNSName Subject
 * Alternative Name (SAN) entry in the leaf certificate passed with the request. The request MUST
 * be signed with the private key corresponding to the public key in the leaf X.509 certificate
 * of the certificate chain added to the request in the x5c JOSE header. The Wallet MUST validate
 * the signature and the trust chain of the X.509 certificate."
 */
class X509SanDnsClientHandler : ClientIdentifierHandler {

    override val prefixes = setOf(ClientIdPrefix.X509_SAN_DNS)

    override suspend fun verify(request: PresentationRequest, identifier: ClientIdentifier, policy: PresentationRequestPolicy): VerifierIdentity {
        val jwt = signedRequestObject(request, identifier.prefix)
        val chain = RequestObjectCertificates.chain(jwt)
            ?: throw PresentationRequestException.ClientNotVerified("the request object carries no x5c certificate chain")
        val leaf = chain.first()

        if (!RequestObjectCertificates.verifySignature(jwt, leaf.publicKey)) {
            throw PresentationRequestException.ClientNotVerified("the request object is not signed with the leaf certificate's key")
        }
        if (RequestObjectCertificates.dnsNames(leaf).none { it.equals(identifier.identifier, ignoreCase = true) }) {
            throw PresentationRequestException.ClientNotVerified("${identifier.identifier} is not a dNSName SAN of the leaf certificate")
        }
        val anchored = RequestObjectCertificates.checkChain(chain, policy.trustAnchors)

        val target = request.responseUri?.takeIf { it.isNotBlank() } ?: request.redirectUri
        val bound = target?.let { runCatching { URI(it).host }.getOrNull()?.equals(identifier.identifier, ignoreCase = true) }

        return VerifierIdentity(
            identifier = identifier,
            verified = true,
            anchored = anchored,
            certificateChain = chain,
            redirectUriBound = bound,
            reason = if (anchored) null else "no trust anchors configured; the chain was checked for consistency only",
        )
    }
}
