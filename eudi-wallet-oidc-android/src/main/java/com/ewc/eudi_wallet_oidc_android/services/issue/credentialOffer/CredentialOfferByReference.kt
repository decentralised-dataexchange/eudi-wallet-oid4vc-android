package com.ewc.eudi_wallet_oidc_android.services.issue.credentialOffer

import android.net.Uri
import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.WrappedCredentialOffer
import com.ewc.eudi_wallet_oidc_android.services.UrlUtils
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.utils.ErrorHandler
import androidx.core.net.toUri
import com.ewc.eudi_wallet_oidc_android.services.UriValidationFailed

class CredentialOfferByReference : CredentialOfferHandler {
    override suspend fun processCredentialOffer(credentialOfferData: String): WrappedCredentialOffer? {
        try {
            val uri = credentialOfferData.toUri()
            val credentialOfferUri = uri.getQueryParameter("credential_offer_uri")
            if (!credentialOfferUri.isNullOrBlank()) {
                UrlUtils.validateUri(credentialOfferUri)
                val response =
                    ApiManager.api.getService()?.resolveCredentialOffer(credentialOfferUri)
                return if (response?.isSuccessful == true) {
                    WrappedCredentialOffer(
                        credentialOffer = ParseCredentialOffer().parse(
                            credentialOfferJson = response.body()?.string()
                        )
                    )

                } else {
                    WrappedCredentialOffer(
                        errorResponse = ErrorHandler.processError(response?.errorBody()?.string())
                    )
                }
            }else {
                return null
            }
        } catch (exc: UriValidationFailed) {
            return null
        } catch (e: Exception) {
            Log.d("Exception", e.message.toString())
            return null
        }
    }
}