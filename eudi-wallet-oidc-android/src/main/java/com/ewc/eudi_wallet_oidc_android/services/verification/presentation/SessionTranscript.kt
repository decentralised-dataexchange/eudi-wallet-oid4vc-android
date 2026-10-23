package com.ewc.eudi_wallet_oidc_android.services.verification.presentation

import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.UnicodeString
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.ResponseModes
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * The ISO 18013-5 SessionTranscript an mdoc device signature is bound to, in the shapes
 * OpenID4VP 1.0 Appendix B.2.6 defines and the one ISO/IEC TS 18013-7 Annex B defines.
 *
 * All three are `[null, null, Handover]`: "DeviceEngagementBytes MUST be null. EReaderKeyBytes
 * MUST be null." They differ in the handover.
 */
class SessionTranscript private constructor(val array: CborArray) {

    val bytes: ByteArray by lazy { encode(array) }

    companion object {

        /**
         * B.2.6.1, redirect flows: `Handover = ["OpenID4VPHandover", sha256(OpenID4VPHandoverInfo)]`
         * with `OpenID4VPHandoverInfo = [client_id, nonce, jwk_thumbprint or null, response_uri]`.
         * "The fourth element MUST be either the redirect_uri or response_uri request parameter,
         * depending on which is present."
         */
        fun openId4Vp(clientId: String, nonce: String, responseUri: String, encryptionKeyThumbprint: ByteArray?): SessionTranscript =
            withHandover("OpenID4VPHandover", CborArray().apply {
                add(UnicodeString(clientId))
                add(UnicodeString(nonce))
                add(encryptionKeyThumbprint?.let { ByteString(it) } ?: SimpleValue.NULL)
                add(UnicodeString(responseUri))
            })

        /**
         * B.2.6.2, Digital Credentials API: `Handover = ["OpenID4VPDCAPIHandover", sha256(info)]`
         * with `info = [origin, nonce, jwk_thumbprint or null]`. "The first element MUST be the
         * string representing the Origin of the request. It MUST NOT be prefixed with origin:."
         */
        fun dcApi(origin: String, nonce: String, encryptionKeyThumbprint: ByteArray?): SessionTranscript =
            withHandover("OpenID4VPDCAPIHandover", CborArray().apply {
                add(UnicodeString(origin))
                add(UnicodeString(nonce))
                add(encryptionKeyThumbprint?.let { ByteString(it) } ?: SimpleValue.NULL)
            })

        /**
         * ISO/IEC TS 18013-7 section B.4.4, the draft profile used with a presentation
         * definition: `Handover = [clientIdHash, responseUriHash, nonce]` where
         * `clientIdHash = sha256(cbor([client_id, mdocGeneratedNonce]))` and
         * `responseUriHash = sha256(cbor([response_uri, mdocGeneratedNonce]))`.
         *
         * The profile wants a random `mdocGeneratedNonce` echoed to the verifier as the JWE `apu`
         * header. The response encryption sets `apu` to the client id, so the default here keeps
         * both ends consistent; a random nonce needs both places changed together.
         */
        fun annexB(clientId: String, nonce: String, responseUri: String, mdocGeneratedNonce: String = clientId): SessionTranscript {
            val handover = CborArray().apply {
                add(ByteString(sha256(encode(strings(clientId, mdocGeneratedNonce)))))
                add(ByteString(sha256(encode(strings(responseUri, mdocGeneratedNonce)))))
                add(UnicodeString(nonce))
            }
            return SessionTranscript(transcript(handover))
        }

        /**
         * The transcript the request calls for: Annex B when it carries a presentation
         * definition, the DC API handover for the `dc_api` response modes, the OpenID4VP handover
         * otherwise.
         */
        fun forRequest(request: PresentationRequest, encryptionKeyThumbprint: ByteArray?): SessionTranscript {
            val nonce = request.nonce ?: ""
            val isDcApi = request.responseMode == ResponseModes.DC_API.value || request.responseMode == ResponseModes.DC_API_JWT.value
            val clientId = (request.clientId ?: "").let { if (isDcApi) it.removePrefix("origin:") else it }
            val responseUri = request.responseUri ?: request.redirectUri ?: ""
            val usesPresentationDefinition = request.presentationDefinition != null || request.presentationDefinitionUri != null
            return when {
                usesPresentationDefinition -> annexB(clientId, nonce, responseUri)
                isDcApi -> dcApi(clientId, nonce, encryptionKeyThumbprint)
                else -> openId4Vp(clientId, nonce, responseUri, encryptionKeyThumbprint)
            }
        }

        private fun withHandover(label: String, info: CborArray): SessionTranscript {
            val handover = CborArray().apply {
                add(UnicodeString(label))
                add(ByteString(sha256(encode(info))))
            }
            return SessionTranscript(transcript(handover))
        }

        private fun transcript(handover: CborArray) = CborArray().apply {
            add(SimpleValue.NULL)
            add(SimpleValue.NULL)
            add(handover)
        }

        private fun strings(vararg values: String) = CborArray().apply { values.forEach { add(UnicodeString(it)) } }

        private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

        internal fun encode(item: DataItem): ByteArray =
            ByteArrayOutputStream().also { CborEncoder(it).encode(item) }.toByteArray()
    }
}
