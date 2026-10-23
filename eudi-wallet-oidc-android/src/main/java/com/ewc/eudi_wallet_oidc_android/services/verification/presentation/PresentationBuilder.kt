package com.ewc.eudi_wallet_oidc_android.services.verification.presentation

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse.VerifierJwk
import com.ewc.eudi_wallet_oidc_android.services.verification.deviceSigned.JWKThumbprint
import com.google.gson.Gson
import com.nimbusds.jwt.JWTParser

/**
 * Turns the credentials the user selected into the elements of a `vp_token`.
 *
 * Credentials are presented in the order given. SD-JWTs and, under DCQL, mdocs and W3C VCs each
 * become one presentation. Under a presentation definition the draft shapes apply: every mdoc
 * still gets its own DeviceResponse, but several W3C VCs are aggregated into one presentation
 * placed where the first of them was.
 *
 * @param lenient when true, a credential whose proof cannot be made is presented as it is, with a
 *   warning, which is what the previous API did. The new API refuses the response instead.
 */
class PresentationBuilder(
    private val sdJwt: SdJwtVpTokenBuilder = SdJwtVpTokenBuilder(),
    private val jwtVp: JwtVpTokenBuilder = JwtVpTokenBuilder(),
    private val mdoc: MdocVpTokenBuilder = MdocVpTokenBuilder(),
    private val lenient: Boolean = false,
) {

    /**
     * @throws PresentationException when not lenient and a proof cannot be made.
     */
    suspend fun build(selected: List<SelectedCredential>, inputs: PresentationInputs): List<Presentation> {
        if (selected.isEmpty()) return emptyList()
        val withFormat = selected.map { it to formatOf(it) }
        val transcript by lazy { SessionTranscript.forRequest(inputs.request, inputs.encryptionKeyThumbprint) }
        val aggregateW3c = inputs.request.dcqlQuery == null && withFormat.count { it.second == PresentationFormat.W3C_VP } > 1

        val out = mutableListOf<Presentation>()
        var w3cDone = false
        withFormat.forEach { (credential, format) ->
            when (format) {
                PresentationFormat.SD_JWT -> out += attempt(credential, format) { sdJwt.present(credential, inputs) }
                PresentationFormat.MDOC -> out += attempt(credential, format) { mdoc.present(credential, inputs, transcript) }
                PresentationFormat.W3C_VP -> if (aggregateW3c) {
                    if (!w3cDone) {
                        w3cDone = true
                        val all = withFormat.filter { it.second == PresentationFormat.W3C_VP }.map { it.first }
                        out += attempt(credential, format) { jwtVp.aggregate(all, inputs) }
                    }
                } else {
                    out += attempt(credential, format) { jwtVp.present(credential, inputs) }
                }
                null -> if (lenient) {
                    Logger.w(TAG, "Credential for ${credential.entryId} has no recognised format; presented as it is")
                    out += Presentation(listOf(credential.entryId), PresentationFormat.SD_JWT, credential.credential)
                } else throw PresentationException.UnsupportedFormat(credential.entryId)
            }
        }
        return out
    }

    private inline fun attempt(credential: SelectedCredential, format: PresentationFormat, block: () -> Presentation): Presentation =
        try {
            block()
        } catch (e: PresentationException) {
            if (!lenient) throw e
            Logger.w(TAG, "${e.message}; the credential is presented without a proof")
            Presentation(listOf(credential.entryId), format, credential.credential)
        }

    /** mdoc when there is no `.`, SD-JWT when there is a `~` or a `vct`, W3C VC for any other JWT. */
    private fun formatOf(selected: SelectedCredential): PresentationFormat? {
        val raw = selected.credential
        if (raw.isBlank()) return null
        if (!raw.contains('.')) return PresentationFormat.MDOC
        if (raw.contains('~')) return PresentationFormat.SD_JWT
        return try {
            if (JWTParser.parse(raw).jwtClaimsSet.getClaim("vct") != null) PresentationFormat.SD_JWT else PresentationFormat.W3C_VP
        } catch (e: Exception) {
            null
        }
    }

    companion object {
        private const val TAG = "PresentationBuilder"

        /**
         * The RFC 7638 thumbprint of the verifier's encryption key from the request's client
         * metadata, for the mdoc session transcript; null when there is none.
         */
        suspend fun encryptionKeyThumbprint(request: PresentationRequest): ByteArray? = try {
            val metadata = Gson().toJsonTree(request.clientMetaDetails).asJsonObject
            val algorithm = VerifierJwk.deriveJWEAlgorithmFromClientMetadata(metadata)
            VerifierJwk.deriveVerifiersJWKFromClientMetadata(metadata, algorithm)?.let { JWKThumbprint.computeJwkThumbprintBytes(it) }
        } catch (e: Exception) {
            null
        }
    }
}
