package com.ewc.eudi_wallet_oidc_android.services.verification.presentation

/**
 * An SD-JWT presentation: the SD-JWT as selected by the wallet, followed by the key binding JWT
 * (SD-JWT VC, OpenID4VP 1.0 Appendix B.3.6).
 */
class SdJwtVpTokenBuilder {

    /**
     * @throws PresentationException.NoKey
     * @throws PresentationException.KeyBindingFailed
     */
    fun present(selected: SelectedCredential, inputs: PresentationInputs): Presentation {
        val key = selected.key ?: inputs.holder?.jwk ?: throw PresentationException.NoKey(selected.entryId)
        val presented = if (selected.credential.endsWith("~")) selected.credential else selected.credential + "~"
        val keyBinding = KeyBindingJwt.sign(
            entryId = selected.entryId,
            presented = presented,
            key = key,
            audience = inputs.request.clientId,
            nonce = inputs.request.nonce,
            transactionDataHashes = inputs.transactionDataHashes[selected.entryId],
            scaResponseMode = if (inputs.strongCustomerAuthentication) inputs.request.responseMode else null,
            amr = if (inputs.strongCustomerAuthentication) (inputs.authentication ?: AuthenticationMethods()).amr() else null,
        )
        return Presentation(listOf(selected.entryId), PresentationFormat.SD_JWT, presented + keyBinding)
    }
}
