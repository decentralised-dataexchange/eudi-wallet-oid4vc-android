package com.ewc.eudi_wallet_oidc_android.services.verification.clientIdSchemeHandling

import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest

interface ClientIdSchemeHandler {
    suspend fun validate(wrappedPresentationRequest: WrappedPresentationRequest): WrappedPresentationRequest
    fun update(wrappedPresentationRequest: WrappedPresentationRequest): WrappedPresentationRequest
}