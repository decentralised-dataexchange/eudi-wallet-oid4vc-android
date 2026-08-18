package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation


import android.content.Context
import com.ewc.eudi_wallet_oidc_android.WalletAttestationResult
import com.nimbusds.jose.jwk.ECKey

/**
 * Deprecated facade kept for published-API compatibility.
 * All WUA logic now lives in [WalletUnitAttestationService] and [WalletUnitAttestationHeaders].
 */
@Deprecated("WUA logic moved to WalletUnitAttestationService")
object WalletAttestationUtil {
    val TAG = WalletUnitAttestationService.TAG

    // Legacy behavior: generateClientAssertion(ecKey, did) uses the baseUrl of the
    // last initiateWalletUnitAttestation call as the audience claim.
    private var baseUrl: String? = null


    @Deprecated(
        "Use WalletUnitAttestationService.initiateWalletUnitAttestation",
        ReplaceWith("WalletUnitAttestationService.initiateWalletUnitAttestation(context, cloudProjectNumber, baseUrl, inputEcKey)")
    )
    suspend fun initiateWalletUnitAttestation(
        context: Context,
        cloudProjectNumber: Long,
        baseUrl: String,
        inputEcKey: ECKey?
    ): WalletAttestationResult? {
        this.baseUrl = baseUrl
        return WalletUnitAttestationService.initiateWalletUnitAttestation(
            context, cloudProjectNumber, baseUrl, inputEcKey
        )
    }

    @Deprecated(
        "Use WalletUnitAttestationService.generateClientAssertion with an explicit audience",
        ReplaceWith("WalletUnitAttestationService.generateClientAssertion(ecKey, did, audience)")
    )
    fun generateClientAssertion(
        ecKey: ECKey,
        did: String?
    ): String {
        return WalletUnitAttestationService.generateClientAssertion(ecKey, did, audience = baseUrl)
    }

    @Deprecated(
        "Use WalletUnitAttestationService.generateWUAProofOfPossession",
        ReplaceWith("WalletUnitAttestationService.generateWUAProofOfPossession(ecKey, did, aud)")
    )
    fun generateWUAProofOfPossession(
        ecKey: ECKey,
        did: String?,
        aud: String?
    ): String? {
        return WalletUnitAttestationService.generateWUAProofOfPossession(ecKey, did, aud)
    }

}
