package com.ewc.eudi_wallet_oidc_android.services.issue.credentialOffer

import android.util.Log
import androidx.core.net.toUri
import com.ewc.eudi_wallet_oidc_android.models.WrappedCredentialOffer
import com.ewc.eudi_wallet_oidc_android.services.UriValidationFailed

class CredentialOfferByValue : CredentialOfferHandler {
    override suspend fun processCredentialOffer(credentialOfferData: String): WrappedCredentialOffer? {
        try {
            val uri = credentialOfferData.toUri()
            val credentialOfferString = uri.getQueryParameter("credential_offer")
            if (!credentialOfferString.isNullOrBlank()) {
                return WrappedCredentialOffer(
                    credentialOffer = ParseCredentialOffer().parse(
                        credentialOfferJson = credentialOfferString
                    )
                )
            }
        } catch (exc: UriValidationFailed) {
            return null
        } catch (e: Exception) {
            Log.d("Exception", e.message.toString())
            return null
        }
        return WrappedCredentialOffer(credentialOffer = null, errorResponse = null)
    }
}