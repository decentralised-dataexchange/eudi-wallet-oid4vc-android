package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation

import android.content.Context
import com.ewc.eudi_wallet_oidc_android.BatchWalletAttestationResult
import com.ewc.eudi_wallet_oidc_android.WalletAttestationResult
import com.ewc.eudi_wallet_oidc_android.models.ErrorCodes
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.WalletProviderOutcome
import com.ewc.eudi_wallet_oidc_android.models.WalletUnitRevocationCodeOutcome
import com.ewc.eudi_wallet_oidc_android.models.WalletUnitStatusOutcome
import com.nimbusds.jose.jwk.ECKey

/**
 * Protocol 1 through [WalletUnitAttestationService], for an app that must go
 * back from [WalletProviderClient]: every WIA request carries a Standard Play
 * Integrity token, nothing is signed, and the wallet provider has no unit
 * status and no revocation code (both answer `NotSupported`).
 *
 * The requests behave as the old service does. The single route signs the
 * client assertion with `cnfKey` and names the unit by the did:key of that
 * key, so pass the key whose did:key is `clientId`. An HTTP refusal comes back
 * as `Failed` with `httpStatus` and no `errorId`.
 */
class Protocol1WalletProviderClient internal constructor(
    /** The wallet provider address as the app passes it to the old service. */
    override val baseUrl: String,
    private val service: Protocol1WalletUnitAttestation
) : WalletUnitAttestationProvider {

    constructor(context: Context, baseUrl: String, cloudProjectNumber: Long) : this(
        baseUrl,
        ServiceProtocol1(context.applicationContext, cloudProjectNumber)
    )

    override val isKeyLost: Boolean get() = false

    override suspend fun requestWalletUnitAttestation(
        cnfKey: ECKey,
        clientId: String,
        profile: String?
    ): WalletProviderOutcome<WalletAttestationResult> {
        val result = service.single(baseUrl, cnfKey, profile)
        return if (result == null || (result.walletUnitAttestation.isNullOrEmpty() && result.credentialOffer.isNullOrEmpty())) {
            WalletProviderOutcome.Failed(failure("The wallet provider gave no attestation"))
        } else {
            WalletProviderOutcome.Success(result)
        }
    }

    override suspend fun requestWalletUnitAttestations(
        cnfKeys: List<ECKey>,
        clientId: String,
        profile: String?
    ): WalletProviderOutcome<BatchWalletAttestationResult> {
        if (cnfKeys.isEmpty()) return WalletProviderOutcome.Failed(failure("No key for the batch request"))
        val result = service.batch(baseUrl, cnfKeys, clientId, profile)
            ?: return WalletProviderOutcome.Failed(failure("The batch request could not be made"))
        val refused = result.httpCode?.let { it !in 200..299 } ?: true
        return if (refused && result.units.none { !it.walletUnitAttestation.isNullOrEmpty() }) {
            WalletProviderOutcome.Failed(
                failure(result.errorBody ?: "The wallet provider refused the batch request")
                    .apply { httpStatus = result.httpCode }
            )
        } else {
            WalletProviderOutcome.Success(result)
        }
    }

    override suspend fun status(withEvidence: Boolean): WalletUnitStatusOutcome = WalletUnitStatusOutcome.NotSupported

    override suspend fun revocationCode(): WalletUnitRevocationCodeOutcome = WalletUnitRevocationCodeOutcome.NotSupported

    /** Protocol 1 keeps no unit state of its own. */
    override suspend fun reset() {}

    private fun failure(description: String) =
        ErrorResponse(error = ErrorCodes.WALLET_PROVIDER_REQUEST_FAILED, errorDescription = description)
}

/** The two requests of [WalletUnitAttestationService] that [Protocol1WalletProviderClient] uses; a seam for tests. */
internal interface Protocol1WalletUnitAttestation {
    suspend fun single(baseUrl: String, cnfKey: ECKey, profile: String?): WalletAttestationResult?

    suspend fun batch(baseUrl: String, cnfKeys: List<ECKey>, clientId: String, profile: String?): BatchWalletAttestationResult?
}

private class ServiceProtocol1(
    private val context: Context,
    private val cloudProjectNumber: Long
) : Protocol1WalletUnitAttestation {
    override suspend fun single(baseUrl: String, cnfKey: ECKey, profile: String?) =
        WalletUnitAttestationService.initiateWalletUnitAttestation(
            context, cloudProjectNumber, baseUrl, inputEcKey = cnfKey, profile = profile
        )

    override suspend fun batch(baseUrl: String, cnfKeys: List<ECKey>, clientId: String, profile: String?) =
        WalletUnitAttestationService.initiateBatchWalletUnitAttestation(
            context, cloudProjectNumber, baseUrl, count = cnfKeys.size, profile = profile,
            clientId = clientId, keys = cnfKeys
        )
}
