package com.ewc.eudi_wallet_oidc_android.services.issue.credential

import com.ewc.eudi_wallet_oidc_android.models.CredentialDefinition
import com.ewc.eudi_wallet_oidc_android.models.CredentialRequest
import com.ewc.eudi_wallet_oidc_android.models.ProofV3
import com.ewc.eudi_wallet_oidc_android.models.ProofsV3
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.credentialResponseEncryption.CredentialEncryptionBuilder
import com.google.gson.Gson
import org.json.JSONObject

/**
 * The credential request body, assembled once.
 *
 * The shape is chosen by the [CredentialSubject], which the token response determines -- so the
 * four-branch `if`/`else` chain this replaces becomes a `when` over three cases, and the two
 * identifiers section 8.2 declares mutually exclusive can no longer both be set.
 */
internal object CredentialRequestParameters {

    private const val PROOF_TYPE_JWT = "jwt"

    fun build(
        subject: CredentialSubject,
        proof: String,
        session: IssuanceSession,
        encryption: CredentialEncryption?,
        policy: CredentialRequestPolicy,
    ): CredentialRequest {
        val request = when (subject) {
            is CredentialSubject.ByIdentifier ->
                CredentialRequest(credentialIdentifier = subject.credentialIdentifier)

            is CredentialSubject.ByConfiguration ->
                CredentialRequest(credentialConfigurationId = subject.credentialConfigurationId)

            is CredentialSubject.LegacyFormat -> CredentialRequest(
                format = subject.format,
                types = subject.types?.let { ArrayList(it) },
                credentialDefinition = subject.credentialDefinitionTypes
                    ?.let { CredentialDefinition(type = ArrayList(it)) },
                vct = subject.vct,
                doctype = subject.docType,
            )
        }

        // Section 8.2: "The `proofs` parameter MUST be present if the `proof_types_supported`
        // parameter is present in the `credential_configurations_supported` parameter of the Issuer
        // metadata." Both platforms previously keyed this off whether an arbitrary configuration
        // carried a `credential_metadata` member, which is unrelated to whether the issuer wants
        // the plural form.
        if (policy.usePluralProofs && declaresProofTypes(session, subject)) {
            request.proofs = ProofsV3(jwt = listOf(proof))
        } else {
            request.proof = ProofV3(proofType = PROOF_TYPE_JWT, jwt = proof)
        }

        request.credentialResponseEncryption =
            CredentialEncryptionBuilder().build(encryption?.responseKey)

        return request
    }

    /**
     * Whether the issuer declares `proof_types_supported` for **the credential being requested**.
     *
     * Reuses the navigation `KeyAttestationService.getRequirement` already does for
     * `key_attestations_required`, one level up: the same map, the same matching rule for the map
     * and list metadata shapes.
     */
    fun declaresProofTypes(session: IssuanceSession, subject: CredentialSubject): Boolean {
        val type = configurationIdOf(subject) ?: return false
        val supported = session.issuerConfig?.credentialsSupported ?: return false
        val configuration = runCatching {
            val json = JSONObject(Gson().toJson(mapOf("credentials_supported" to supported)))
            when (val entries = json.opt("credentials_supported")) {
                is JSONObject -> entries.optJSONObject(type)
                is org.json.JSONArray -> (0 until entries.length())
                    .map { entries.getJSONObject(it) }
                    .firstOrNull { (it.optString("id")).contains(type) }
                else -> null
            }
        }.getOrNull() ?: return false

        return configuration.optJSONObject("proof_types_supported") != null
    }

    /** The configuration id a subject names, for metadata lookups. */
    fun configurationIdOf(subject: CredentialSubject): String? = when (subject) {
        is CredentialSubject.ByConfiguration -> subject.credentialConfigurationId
        is CredentialSubject.ByIdentifier -> subject.credentialIdentifier
        is CredentialSubject.LegacyFormat -> subject.types?.firstOrNull()
            ?: subject.credentialDefinitionTypes?.firstOrNull()
    }
}
