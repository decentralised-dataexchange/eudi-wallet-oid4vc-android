package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation

import com.ewc.eudi_wallet_oidc_android.BatchWalletAttestationResult
import com.ewc.eudi_wallet_oidc_android.WalletAttestationResult
import com.ewc.eudi_wallet_oidc_android.models.WalletProviderOutcome
import com.ewc.eudi_wallet_oidc_android.models.WalletUnitRevocationCodeOutcome
import com.ewc.eudi_wallet_oidc_android.models.WalletUnitStatusOutcome
import com.nimbusds.jose.jwk.ECKey

/**
 * The wallet provider requests of a wallet unit: wallet instance attestations
 * (WIA), the unit status and the revocation code.
 *
 * Two implementations:
 * - [WalletProviderClient]: protocol 2 (signed requests, device evidence,
 *   status and revocation code).
 * - [Protocol1WalletProviderClient]: protocol 1, through
 *   [WalletUnitAttestationService]. It has no status and no revocation code.
 *
 * An app holds one provider and makes it in one place, so switching protocol
 * is a change of that one line. Pass the same provider to
 * [KeyAttestationService] so key attestation speaks the same protocol.
 */
interface WalletUnitAttestationProvider {

    /** The wallet provider address the requests go to. */
    val baseUrl: String

    /**
     * True when the unit was registered but its device key is gone from the
     * device (a restored backup, a new phone): the app must start a new unit.
     */
    val isKeyLost: Boolean

    /**
     * One WIA bound to [cnfKey] (private part included: it signs the client
     * assertion), whose client assertion names the wallet unit by [clientId].
     * The answer of a registration carries the revocation code.
     */
    suspend fun requestWalletUnitAttestation(
        cnfKey: ECKey,
        clientId: String,
        profile: String? = null
    ): WalletProviderOutcome<WalletAttestationResult>

    /**
     * One WIA for each key of [cnfKeys], index-aligned with the keys. Every
     * client assertion names the wallet unit by [clientId].
     */
    suspend fun requestWalletUnitAttestations(
        cnfKeys: List<ECKey>,
        clientId: String,
        profile: String? = null
    ): WalletProviderOutcome<BatchWalletAttestationResult>

    /** The unit status. [withEvidence]: send device evidence with the read. */
    suspend fun status(withEvidence: Boolean): WalletUnitStatusOutcome

    /** The revocation code of a registered unit that has none yet. */
    suspend fun revocationCode(): WalletUnitRevocationCodeOutcome

    /** Forgets the keys of the unit: the next WIA request registers a new one. */
    suspend fun reset()
}
