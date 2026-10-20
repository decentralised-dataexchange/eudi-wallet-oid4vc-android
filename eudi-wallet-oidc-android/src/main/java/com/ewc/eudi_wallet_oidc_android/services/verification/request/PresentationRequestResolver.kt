package com.ewc.eudi_wallet_oidc_android.services.verification.request

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.dcql.DcqlQueryValidator
import com.ewc.eudi_wallet_oidc_android.services.verification.client.ClientIdentifierVerifier
import com.ewc.eudi_wallet_oidc_android.services.verification.request.legacy.ClientMetadataUriResolver
import com.ewc.eudi_wallet_oidc_android.services.verification.request.legacy.PresentationDefinitionUriResolver
import com.ewc.eudi_wallet_oidc_android.services.verification.request.source.InlinePresentationRequestSource
import com.ewc.eudi_wallet_oidc_android.services.verification.request.source.PresentationRequestSource
import com.ewc.eudi_wallet_oidc_android.services.verification.request.source.RemotePresentationRequestSource
import com.ewc.eudi_wallet_oidc_android.services.verification.request.source.RequestObjectSource
import com.ewc.eudi_wallet_oidc_android.services.verification.request.source.extension.InteractiveAuthorizationRequestSource

/**
 * Resolves scanned data into a presentation request: pick a source, retrieve the parameters,
 * validate the query, dereference the draft URIs.
 *
 * The registry is ordered and OpenID4VP 1.0 comes first. Legacy entries are grouped so draft
 * support can be removed as a block. Every failure is a [PresentationRequestOutcome.Failed]
 * carrying a description a user can read, never a bare null.
 *
 * Every source funnels through [complete], so a rule that applies to all of them, such as the
 * DCQL validation and the client identifier check, is written once.
 */
class PresentationRequestResolver(
    private val policy: PresentationRequestPolicy = PresentationRequestPolicy.Default,
    private val sources: List<PresentationRequestSource> = defaultSources(),
    private val presentationDefinitionUriResolver: PresentationDefinitionUriResolver = PresentationDefinitionUriResolver(),
    private val clientMetadataUriResolver: ClientMetadataUriResolver = ClientMetadataUriResolver(),
    private val clientIdentifierVerifier: ClientIdentifierVerifier = ClientIdentifierVerifier(),
) {

    suspend fun resolve(data: String?): PresentationRequestOutcome {
        if (data.isNullOrBlank()) return failure(PresentationRequestException.NoRequest())

        return try {
            val source = select(data)
            val request = source.retrieve(data, policy)
            complete(request, source)
        } catch (e: PresentationRequestException) {
            failure(e)
        } catch (e: Exception) {
            // Nothing above should throw anything else; if it does, the user still gets a message.
            Logger.e(TAG, "Unexpected failure resolving a presentation request", e)
            failure(PresentationRequestException.Malformed(e.message ?: "Invalid Request"))
        }
    }

    private fun select(data: String): PresentationRequestSource {
        // RFC 9101 section 5: "If [request] is present in the authorization request, request_uri
        // MUST NOT be present", and the reverse. Section 10.7 explains why: two copies of the
        // parameters invite a mismatch attack.
        if (policy.rejectAmbiguousRequests &&
            AuthorizationRequestUri.hasValue(data, "request") &&
            AuthorizationRequestUri.hasValue(data, "request_uri")
        ) {
            throw PresentationRequestException.AmbiguousRequest()
        }
        return sources.firstOrNull { it.supports(data) } ?: throw PresentationRequestException.NoRequest()
    }

    private suspend fun complete(request: PresentationRequest, source: PresentationRequestSource): PresentationRequestOutcome {
        // A DCQL query that breaks OpenID4VP 1.0 is refused once, here, before any URI is
        // resolved or any stored credential is read.
        request.dcqlQuery?.let { dcql ->
            val violations = DcqlQueryValidator.validate(dcql)
            if (violations.isNotEmpty()) {
                throw PresentationRequestException.InvalidDcqlQuery(violations.joinToString("; "))
            }
        }

        val hasPresentationDefinition =
            request.presentationDefinition != null || !request.presentationDefinitionUri.isNullOrBlank()
        val specVersion = when {
            request.dcqlQuery != null -> PresentationRequestSpecVersion.V1_0
            hasPresentationDefinition -> PresentationRequestSpecVersion.Draft
            else -> PresentationRequestSpecVersion.V1_0
        }

        if (specVersion == PresentationRequestSpecVersion.V1_0 && hasPresentationDefinition) {
            // 1.0 defines only dcql_query. A verifier sending both gets the 1.0 answer.
            Logger.w(TAG, "Request carries both dcql_query and presentation_definition; the presentation definition is ignored")
            request.presentationDefinition = null
            request.presentationDefinitionUri = null
        }
        if (specVersion == PresentationRequestSpecVersion.Draft && !policy.allowDraftRequests) {
            throw PresentationRequestException.DraftNotAllowed()
        }

        // --- legacy, safe to delete as a block ---
        if (request.presentationDefinition == null && !request.presentationDefinitionUri.isNullOrBlank()) {
            request.presentationDefinition = presentationDefinitionUriResolver.resolve(request.presentationDefinitionUri!!)
        }
        if (request.clientMetaDetails == null && !request.clientMetadataUri.isNullOrBlank()) {
            if (policy.allowDraftRequests) {
                request.clientMetaDetails = clientMetadataUriResolver.resolve(request.clientMetadataUri!!)
            } else {
                Logger.w(TAG, "client_metadata_uri ignored: draft parameters are not allowed by the policy")
            }
        }
        // --- end legacy ---

        // Section 5.9: who the verifier is, by the rules of its client identifier prefix.
        val verifier = clientIdentifierVerifier.verify(request, policy)

        Logger.d(TAG, "Resolved a $specVersion presentation request from ${source.name}")
        return PresentationRequestOutcome.Resolved(request, specVersion, source.name, verifier)
    }

    private fun failure(e: PresentationRequestException): PresentationRequestOutcome.Failed {
        Logger.d(TAG, "Presentation request rejected: ${e.message}")
        return PresentationRequestOutcome.Failed(
            ErrorResponse(error = e.code, errorDescription = e.message, errorCode = e.oauthError)
        )
    }

    companion object {
        private const val TAG = "PresentationRequestResolver"

        /** Ordered: OpenID4VP 1.0 mechanisms first, the issuance profile extension last. */
        fun defaultSources(): List<PresentationRequestSource> = listOf(
            InlinePresentationRequestSource(),
            RemotePresentationRequestSource(),
            RequestObjectSource(),
            // --- extension: EWC interactive authorization request ---
            InteractiveAuthorizationRequestSource(),
        )
    }
}
