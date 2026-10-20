package com.ewc.eudi_wallet_oidc_android.services.verification.presentation

import android.util.Base64
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.UnicodeString
import com.ewc.eudi_wallet_oidc_android.models.DeviceSigned
import com.ewc.eudi_wallet_oidc_android.models.Document
import com.ewc.eudi_wallet_oidc_android.models.IssuerSigned
import com.ewc.eudi_wallet_oidc_android.models.VpToken
import com.ewc.eudi_wallet_oidc_android.services.utils.CborUtils
import com.ewc.eudi_wallet_oidc_android.services.verification.PresentationDefinitionProcessor
import com.ewc.eudi_wallet_oidc_android.services.verification.deviceSigned.buildDeviceAuthenticationBytes
import com.ewc.eudi_wallet_oidc_android.services.verification.deviceSigned.buildDeviceSignatureCoseSign1
import com.ewc.eudi_wallet_oidc_android.services.verification.deviceSigned.buildProtectedHeader
import com.ewc.eudi_wallet_oidc_android.services.verification.deviceSigned.encodeEmptyDeviceNameSpaces
import com.nimbusds.jose.jwk.JWK
import java.security.PrivateKey

/**
 * An mdoc presentation: an ISO 18013-5 DeviceResponse carrying the IssuerSigned the wallet
 * selected and a DeviceSigned structure whose signature binds it to the session transcript
 * (OpenID4VP 1.0 Appendix B.2.6). Base64url encoded, as Appendix B.2.4 requires.
 */
class MdocVpTokenBuilder {

    /** One DeviceResponse with one document, the 1.0 shape. */
    fun present(selected: SelectedCredential, inputs: PresentationInputs, transcript: SessionTranscript): Presentation =
        Presentation(
            entryIds = listOf(selected.entryId),
            format = PresentationFormat.MDOC,
            token = encode(listOf(document(selected, inputs, transcript))),
        )

    /** One DeviceResponse with every document, the draft shape the V1 path used. */
    fun presentAll(selected: List<SelectedCredential>, inputs: PresentationInputs, transcript: SessionTranscript): Presentation =
        Presentation(
            entryIds = selected.map { it.entryId },
            format = PresentationFormat.MDOC,
            token = encode(selected.map { document(it, inputs, transcript) }),
        )

    private fun document(selected: SelectedCredential, inputs: PresentationInputs, transcript: SessionTranscript): Document {
        val key = selected.key ?: inputs.holder?.jwk ?: throw PresentationException.NoKey(selected.entryId)
        val privateKey: PrivateKey = try {
            // A PrivateKey, not an ECPrivateKey: a Keystore key only exposes a handle.
            key.toECKey().toPrivateKey()
        } catch (e: Exception) {
            throw PresentationException.NoKey(selected.entryId)
        } ?: throw PresentationException.NoKey(selected.entryId)

        val one = listOf(selected.credential)
        val docType = CborUtils.extractDocTypeFromIssuerAuth(one)
            ?: inputs.request.takeIf { it.dcqlQuery == null }?.presentationDefinition
                ?.let { PresentationDefinitionProcessor.processPresentationDefinition(it).docType }
            ?: ""
        try {
            val issuerAuth = CborUtils.processExtractIssuerAuth(one)
            val nameSpaces = CborUtils.processExtractNameSpaces(one, inputs.request, docType)
            val emptyDeviceNameSpaces = encodeEmptyDeviceNameSpaces()
            val authentication = buildDeviceAuthenticationBytes(transcript.array, docType, emptyDeviceNameSpaces)
            val signature = buildDeviceSignatureCoseSign1(authentication, buildProtectedHeader(), privateKey)
            val deviceAuth = CborMap().apply { put(UnicodeString("deviceSignature"), signature) }
            return Document(
                docType = docType,
                issuerSigned = IssuerSigned(nameSpaces, issuerAuth),
                deviceSigned = DeviceSigned(emptyDeviceNameSpaces, deviceAuth),
            )
        } catch (e: Exception) {
            throw PresentationException.DeviceSignatureFailed(selected.entryId, e)
        }
    }

    private fun encode(documents: List<Document>): String {
        val response = VpToken(version = "1.0", documents = documents, status = 0)
        return Base64.encodeToString(CborUtils.encodeMDocToCbor(response), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }
}
