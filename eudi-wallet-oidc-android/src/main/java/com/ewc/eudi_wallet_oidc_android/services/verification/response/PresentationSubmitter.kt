package com.ewc.eudi_wallet_oidc_android.services.verification.response

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletAttestation
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletUnitAttestationHeaders
import com.ewc.eudi_wallet_oidc_android.services.verification.PresentationDefinitionProcessor
import com.ewc.eudi_wallet_oidc_android.services.verification.idToken.IdTokenGenerator
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.AuthenticationMethods
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.PresentationBuilder
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.PresentationException
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.PresentationInputs
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.SelectedCredential
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.legacy.PresentationSubmissionBuilder
import com.ewc.eudi_wallet_oidc_android.services.verification.vpTokenBuilders.LegacyTransactionData

/**
 * The response pipeline: response mode, response URI, the presentations, the submission, the id
 * token, the encoding, and then the POST or the hand-over to the host.
 *
 * A proof that cannot be made refuses the whole response and sends nothing: a verifier is never
 * shown an unsigned credential in place of a presentation.
 */
class PresentationSubmitter(
    private val builder: PresentationBuilder = PresentationBuilder(),
    private val encoder: AuthorizationResponseEncoder = AuthorizationResponseEncoder(),
    private val client: DirectPostClient = DirectPostClient(),
) {

    suspend fun submit(
        request: PresentationRequest,
        selected: List<SelectedCredential>,
        identity: WalletIdentity,
        attestation: WalletAttestation? = null,
        authentication: AuthenticationMethods? = null,
    ): PresentationOutcome {
        return try {
            val mode = ResponseMode.of(request)
            if (mode is ResponseMode.Unsupported) throw SubmissionException.UnsupportedResponseMode(mode.raw)
            // Appendix A.4: over the DC API the audience is the origin, prefixed. Applied on a
            // copy so the caller's request is not changed under it.
            val effective = if (mode.deliveredByHost) request.copy(clientId = "origin:${request.clientId}") else request
            val responseUri = effective.responseUri?.takeIf { it.isNotBlank() } ?: effective.redirectUri?.takeIf { it.isNotBlank() }
            if (!mode.deliveredByHost && responseUri == null) throw SubmissionException.NoResponseUri()

            val fields = prepare(
                request = effective,
                mode = mode,
                selected = selected,
                identity = identity,
                authentication = authentication,
                strongCustomerAuthentication = authentication != null || LegacyTransactionData.isStrongCustomerAuthentication(effective),
            )
            if (mode.deliveredByHost) {
                PresentationOutcome.Delivered(fields)
            } else {
                client.post(responseUri!!, fields, WalletUnitAttestationHeaders.build(attestation?.attestationJwt, attestation?.proofOfPossession))
            }
        } catch (e: PresentationException) {
            refused(e.message, "invalid_request")
        } catch (e: SubmissionException) {
            refused(e.message, e.oauthError)
        }
    }

    /**
     * The encoded response parameters for [mode], without sending them.
     *
     * @throws PresentationException when a proof cannot be made
     * @throws SubmissionException when the response cannot be encoded for the mode
     */
    suspend fun prepare(
        request: PresentationRequest,
        mode: ResponseMode,
        selected: List<SelectedCredential>,
        identity: WalletIdentity,
        authentication: AuthenticationMethods?,
        strongCustomerAuthentication: Boolean,
    ): Map<String, String> {
        val inputs = PresentationInputs(
            request = request,
            holder = identity,
            transactionDataHashes = transactionDataHashes(request),
            strongCustomerAuthentication = strongCustomerAuthentication,
            authentication = authentication,
            encryptionKeyThumbprint = PresentationBuilder.encryptionKeyThumbprint(request),
        )
        val presentations = if (request.responseType?.contains("vp_token") != false) builder.build(selected, inputs) else emptyList()
        val submission = request.takeIf { it.dcqlQuery == null }?.presentationDefinition?.let { definition ->
            PresentationSubmissionBuilder().build(presentations, PresentationDefinitionProcessor.processPresentationDefinition(definition))
        }
        val idToken = if (request.responseType?.contains("id_token") == true) IdTokenGenerator().generateIdToken(request, identity.did, identity.jwk) else null
        val response = AuthorizationResponse.build(request, presentations, submission, idToken)
        return encoder.encode(mode, response, request)
    }

    /** Per entry id, the hashes of the transaction data entries that name it. The first-entry rule holds until the transaction data leg. */
    private fun transactionDataHashes(request: PresentationRequest): Map<String, List<String>> {
        val entries: List<Pair<String, Any>> = request.dcqlQuery?.credentials?.map { (it.id ?: "") to it }
            ?: request.takeIf { it.presentationDefinition != null }?.let { r ->
                PresentationDefinitionProcessor.processPresentationDefinition(r.presentationDefinition).inputDescriptors?.map { (it.id ?: "") to it }
            }.orEmpty()
        return entries.associate { (id, entry) -> id to LegacyTransactionData.hashesFor(entry, request) }
    }

    private fun refused(message: String?, code: String): PresentationOutcome.Refused {
        Logger.d(TAG, "Presentation not sent: $message")
        return PresentationOutcome.Refused(ErrorResponse(errorDescription = message, errorCode = code))
    }

    private companion object {
        const val TAG = "PresentationSubmitter"
    }
}
