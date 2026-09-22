package com.ewc.eudi_wallet_oidc_android.services.reissuance

import com.ewc.eudi_wallet_oidc_android.services.issue.ClientIdentity
import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.AuthorizationDetail
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.CredentialRequestEncryptionInfo
import com.ewc.eudi_wallet_oidc_android.models.ECKeyWithAlgEnc
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedCredentialResponse
import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.Credential
import com.ewc.eudi_wallet_oidc_android.models.CredentialResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletAttestation
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.ewc.eudi_wallet_oidc_android.services.issue.credential.CredentialEncryption
import com.ewc.eudi_wallet_oidc_android.services.issue.credential.CredentialOutcome
import com.ewc.eudi_wallet_oidc_android.services.issue.credential.CredentialSubject
import com.ewc.eudi_wallet_oidc_android.services.issue.IssueService
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.KeyAttestationService
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK

class ReIssuanceService : ReIssuanceServiceInterface {
    override suspend fun reIssueCredential(
        did: String?,
        subJwk: JWK?,
        nonce: String?,
        credentialOffer: CredentialOffer?,
        issuerConfig: IssuerWellKnownConfiguration?,
        accessToken: TokenResponse?,
        authorizationDetail: AuthorizationDetail?,
        index: Int,
        ecKeyWithAlgEnc: ECKeyWithAlgEnc?,
        credentialRequestEncryptionInfo: CredentialRequestEncryptionInfo?,
        interactiveAuthorizationEndpoint: String?,
        dpopKey: ECKey?,
        attachKeyAttestation: Boolean,
        keyAttestationJwt: String?,
        clientId: String?,
        preAuthorizedGrantAnonymousAccessSupported: Boolean?
    ): WrappedCredentialResponse? {
        // Re-issuance is a credential request with a fresh proof; only where the inputs come from
        // differs -- a stored credential record rather than a live offer. It used to be a second
        // copy of the whole leg: its own four-branch subject selection, its own plural-proofs
        // trigger (a *third* condition, `encryptionRequired != null || interactiveAuthorizationEndpoint
        // != null`, true even when encryption_required is false), its own SafeApiCall transport and
        // its own response parsing. All of that now goes through the one implementation.
        val session = IssuanceSession(
            credentialOffer = credentialOffer,
            issuerConfig = issuerConfig,
            authConfig = AuthorisationServerWellKnownConfiguration().apply {
                this.preAuthorizedGrantAnonymousAccessSupported =
                    preAuthorizedGrantAnonymousAccessSupported
            },
        )
        val token = accessToken ?: TokenResponse()
        val credential = credentialOffer?.credentials?.getOrNull(index)

        // Appendix F.1: iss is the original grant's client_id, omitted when that token was anonymous.
        val issuer = ClientIdentity.proofIssuer(
            credentialOffer, preAuthorizedGrantAnonymousAccessSupported, clientId, did,
        )

        val outcome = IssueService().requestCredential(
            session = session,
            wallet = WalletIdentity(did, subJwk),
            token = token,
            subject = authorizationDetail?.let {
                CredentialSubject.of(session, token.apply { authorizationDetails = arrayListOf(it) }, credential)
            } ?: CredentialSubject.of(session, token, credential),
            issuer = issuer,
            attestation = dpopKey?.let { WalletAttestation(null, null, it) },
            // ARF TS3 v1.5: the wallet-provider-issued KA travels in the proof's key_attestation
            // header, bound to the same c_nonce as the proof.
            keyAttestation = KeyAttestationService.forProof(keyAttestationJwt, attachKeyAttestation),
            encryption = CredentialEncryption(ecKeyWithAlgEnc, credentialRequestEncryptionInfo),
            nonce = nonce,
        )

        return when (outcome) {
            is CredentialOutcome.Issued -> WrappedCredentialResponse(
                credentialResponse = CredentialResponse(
                    credential = outcome.credentials.firstOrNull(),
                    credentials = ArrayList(outcome.credentials.map { Credential(credential = it) }),
                    notificationId = outcome.notificationId,
                    cNonce = outcome.cNonce,
                )
            )

            is CredentialOutcome.Deferred -> WrappedCredentialResponse(
                credentialResponse = CredentialResponse(
                    transactionId = outcome.transactionId,
                    acceptanceToken = outcome.transactionId,
                    interval = outcome.interval,
                )
            )

            is CredentialOutcome.Failed -> WrappedCredentialResponse(errorResponse = outcome.error)
        }
    }
}