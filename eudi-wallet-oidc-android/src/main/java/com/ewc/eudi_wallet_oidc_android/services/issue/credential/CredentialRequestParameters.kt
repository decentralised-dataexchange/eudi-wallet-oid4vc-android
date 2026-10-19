package com.ewc.eudi_wallet_oidc_android.services.issue.credential

import com.ewc.eudi_wallet_oidc_android.models.CredentialDefinition
import com.ewc.eudi_wallet_oidc_android.models.CredentialRequest
import com.ewc.eudi_wallet_oidc_android.models.ProofV3
import com.ewc.eudi_wallet_oidc_android.models.ProofsV3
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.credential.proof.CredentialProofs
import com.ewc.eudi_wallet_oidc_android.services.issue.credentialResponseEncryption.CredentialEncryptionBuilder

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
        proofs: CredentialProofs,
        session: IssuanceSession,
        token: TokenResponse?,
        encryption: CredentialEncryption?,
        policy: CredentialRequestPolicy,
    ): CredentialRequest {
        val request = when (subject) {
            is CredentialSubject.ByIdentifier ->
                CredentialRequest(credentialIdentifier = subject.credentialIdentifier)

            is CredentialSubject.ByConfiguration ->
                CredentialRequest(credentialConfigurationId = subject.credentialConfigurationId)

            is CredentialSubject.LegacyFormat -> {
                // A body that names no credential cannot be satisfied by any issuer of any
                // revision. It is what `CredentialSubject.of` falls through to when a 1.0 issuer
                // gave nothing to name the credential by (no offer entry, no authorization_details),
                // and sending it would put a draft `format` next to 1.0 `proofs`.
                if (subject.namesNothing) {
                    throw CredentialRequestException.Unusable(
                        "The credential request names no credential: the offer entry and the " +
                            "token's authorization_details gave no configuration id or type"
                    )
                }
                CredentialRequest(
                    format = subject.format,
                    types = subject.types?.let { ArrayList(it) },
                    credentialDefinition = subject.credentialDefinitionTypes
                        ?.let { CredentialDefinition(type = ArrayList(it)) },
                    vct = subject.vct,
                    doctype = subject.docType,
                )
            }
        }

        // Section 8.2 of 1.0 defines only the plural `proofs`; the singular `proof` belongs to the
        // drafts (draft 13 has only `proof`, draft 14 accepts either). So `proofs` is the default,
        // and `proof` goes only to an issuer `IssuanceSession.isDraftIssuer` positively identifies
        // as a draft: the same answer that chose the subject's shape above, so the body cannot mix
        // a draft name with 1.0 proofs or the reverse.
        when (proofs) {
            // Section 8.2: the attestation proof type carries the KA itself, and the issuer's
            // c_nonce lives inside it. There is no jwt proof to send.
            is CredentialProofs.Attestation ->
                request.proofs = ProofsV3(attestation = arrayListOf(proofs.keyAttestation))

            is CredentialProofs.Jwt -> {
                // A batch is more than one entry; section 8.2's `proofs` is an array either way.
                // The singular `proof` is the pre-1.0 shape and cannot express a batch at all, so a
                // batch always takes the plural form whatever the issuer's revision -- and a policy
                // that forbids the plural form cannot send a batch. Failing here beats silently
                // issuing one credential of the several the caller asked for.
                val batch = proofs.proofs.size > 1
                if (batch && !policy.usePluralProofs) {
                    throw CredentialRequestException.Unusable(
                        "A batch of ${proofs.proofs.size} proofs needs the plural proofs form, " +
                            "which this CredentialRequestPolicy disables"
                    )
                }
                val plural = policy.usePluralProofs && (batch || !session.isDraftIssuer(token))
                if (plural) {
                    request.proofs = ProofsV3(jwt = proofs.proofs)
                } else {
                    request.proof = ProofV3(proofType = PROOF_TYPE_JWT, jwt = proofs.proofs.firstOrNull())
                }
            }
        }

        request.credentialResponseEncryption =
            CredentialEncryptionBuilder().build(encryption?.responseKey)

        return request
    }

    /**
     * The configuration id a subject names, for metadata lookups.
     *
     * A [CredentialSubject.ByIdentifier] carries an instance the issuer allocated, not a metadata
     * key, so it is looked up by the offer entry it was issued for.
     */
    fun configurationIdOf(subject: CredentialSubject): String? = when (subject) {
        is CredentialSubject.ByConfiguration -> subject.credentialConfigurationId
        is CredentialSubject.ByIdentifier -> subject.metadataKey
        is CredentialSubject.LegacyFormat -> subject.types?.firstOrNull()
            ?: subject.credentialDefinitionTypes?.firstOrNull()
    }
}
