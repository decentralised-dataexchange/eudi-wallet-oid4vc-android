package com.ewc.eudi_wallet_oidc_android.services.verification.response

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.PresentationSubmission
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.Presentation
import com.google.gson.Gson

/**
 * The Authorization Response parameters (OpenID4VP 1.0 section 8.1) before encoding.
 *
 * `vp_token` under DCQL is "a JSON-encoded object containing entries where the key is the id
 * value used for a Credential Query in the DCQL query and the value is an array of one or more
 * Presentations". Under a presentation definition it is the draft shape: one presentation as a
 * string, several as a JSON array, with the `presentation_submission` beside it.
 */
data class AuthorizationResponse(val parameters: Map<String, Any?>) {

    /** True when there is neither a `vp_token` nor an `id_token` to send. */
    val isEmpty: Boolean get() = "vp_token" !in parameters && "id_token" !in parameters

    /** The parameters as form fields: strings as they are, null as empty, anything else as JSON. */
    fun asFormFields(): Map<String, String> = parameters.mapValues { (_, value) ->
        when (value) {
            is String -> value
            null -> ""
            else -> Gson().toJson(value)
        }
    }

    companion object {

        /** The client metadata `version` some draft verifiers send; `draft_23` wants a bare string per entry. */
        private const val DRAFT_23 = "draft_23"

        fun build(
            request: PresentationRequest,
            presentations: List<Presentation>,
            submission: PresentationSubmission?,
            idToken: String?,
        ): AuthorizationResponse {
            val state = request.state ?: ""
            if (request.dcqlQuery != null) {
                val byEntry = linkedMapOf<String, MutableList<String>>()
                presentations.forEach { presentation ->
                    presentation.entryIds.distinct().forEach { id -> byEntry.getOrPut(id) { mutableListOf() }.add(presentation.token) }
                }
                val draft23 = metadataVersion(request) == DRAFT_23
                val vpToken = byEntry.mapValues { (_, tokens) -> if (draft23) tokens.first() else tokens }
                return AuthorizationResponse(mapOf("vp_token" to vpToken, "state" to state))
            }

            val tokens = presentations.map { it.token }
            val vpToken: String = if (tokens.size > 1) Gson().toJson(tokens) else tokens.firstOrNull() ?: ""
            val submissionMap = submission?.let { Gson().fromJson(Gson().toJson(it), HashMap::class.java) }
            return when (request.responseType) {
                "vp_token" -> AuthorizationResponse(mapOf("vp_token" to vpToken, "presentation_submission" to submissionMap, "state" to state))
                "id_token" -> AuthorizationResponse(mapOf("id_token" to (idToken ?: ""), "state" to state))
                "vp_token+id_token", "vp_token id_token" -> AuthorizationResponse(
                    mapOf("vp_token" to vpToken, "id_token" to (idToken ?: ""), "presentation_submission" to submissionMap, "state" to state)
                )
                else -> AuthorizationResponse(emptyMap())
            }
        }

        private fun metadataVersion(request: PresentationRequest): String? = try {
            Gson().toJsonTree(request.clientMetaDetails).asJsonObject.getAsJsonPrimitive("version")?.asString
        } catch (e: Exception) {
            null
        }
    }
}
