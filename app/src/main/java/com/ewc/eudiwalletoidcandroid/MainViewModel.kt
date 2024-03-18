package com.ewc.eudiwalletoidcandroid

import android.net.Uri
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import com.ewc.eudi_wallet_oidc_android.services.codeVerifier.CodeVerifierService
import com.ewc.eudi_wallet_oidc_android.services.did.DIDService
import com.ewc.eudi_wallet_oidc_android.services.discovery.DiscoveryService
import com.ewc.eudi_wallet_oidc_android.services.issue.IssueService
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationService
import com.nimbusds.jose.jwk.ECKey
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Timer
import java.util.TimerTask

class MainViewModel : ViewModel() {

    var isLoading = MutableLiveData<Boolean>(false)

    var isPreAuthorised = MutableLiveData<Boolean>(false)

    var credentialJwt = MutableLiveData<String?>("")

    private lateinit var codeVerifier: String
    private var tokenResponse: TokenResponse? = null
    private var authConfig: AuthorisationServerWellKnownConfiguration? = null
    private var issuerConfig: IssuerWellKnownConfiguration? = null
    private var offerCredential: CredentialOffer? = null
    lateinit var did: String
    lateinit var subJwk: ECKey

    init {
        isLoading.value = false
    }

    fun issueCredential(url: String) {
        isLoading.value = true
        CoroutineScope(Dispatchers.Main).launch {
            // Resolving credential offer
            offerCredential = IssueService().resolveCredentialOffer(url)

            // Discovery
            issuerConfig =
                DiscoveryService().getIssuerConfig(offerCredential?.credentialIssuer)
            authConfig =
                DiscoveryService().getAuthConfig(
                    issuerConfig?.authorizationServer ?: issuerConfig?.issuer
                )

            // Generating code verifier
            codeVerifier = CodeVerifierService().generateCodeVerifier()

            if (offerCredential?.grants?.preAuthorizationCode?.preAuthorizedCode != null) {
                // pre authorized code flow
                if (offerCredential?.grants?.preAuthorizationCode?.userPinRequired == true) {
                    // pre authorized code flow with pin required
                    isPreAuthorised.value = true
                    isLoading.value = false
                } else {
                    // pre authorized code flow with no pin required
                    tokenResponse = IssueService().processTokenRequest(
                        did = did,
                        tokenEndPoint = authConfig?.tokenEndpoint,
                        code = offerCredential?.grants?.preAuthorizationCode?.preAuthorizedCode,
                        codeVerifier = codeVerifier,
                        isPreAuthorisedCodeFlow = true,
                        userPin = null
                    )
                    getCredential()
                }
            } else {
                // Process Authorisation request
                val authResponse = IssueService().processAuthorisationRequest(
                    did,
                    subJwk,
                    offerCredential,
                    codeVerifier,
                    authConfig?.authorizationEndpoint
                )

                val code = Uri.parse(authResponse).getQueryParameter("code")

                //process token request
                tokenResponse = IssueService().processTokenRequest(
                    did = did,
                    tokenEndPoint = authConfig?.tokenEndpoint,
                    code = code,
                    codeVerifier = codeVerifier,
                    isPreAuthorisedCodeFlow = false,
                    userPin = null
                )
                getCredential()
            }

        }
    }

    private suspend fun getCredential() {
        val credential = IssueService().processCredentialRequest(
            did,
            subJwk,
            issuerConfig?.credentialIssuer,
            tokenResponse?.cNonce,
            offerCredential,
            issuerConfig?.credentialEndpoint,
            tokenResponse?.accessToken
        )

        withContext(Dispatchers.Main) {
            if (credential?.credential != null) {
                credentialJwt.value = credential.credential
                isLoading.value = false
            }
        }

        fetchDeferredCredential(credential?.acceptanceToken)
    }

    // fetching deferred credential
    private fun fetchDeferredCredential(acceptanceToken: String?) {
        if (acceptanceToken != null) {
            val timer = Timer()
            timer.scheduleAtFixedRate(object : TimerTask() {
                override fun run() {
                    CoroutineScope(Dispatchers.IO).launch {
                        val credential =
                            IssueService().processDeferredCredentialRequest(
                                acceptanceToken,
                                issuerConfig?.deferredCredentialEndpoint
                            )

                        if (credential?.credential != null) {

                            withContext(Dispatchers.Main) {
                                if (credential.credential != null) {
                                    credentialJwt.value = credential.credential
                                    isLoading.value = false
                                }
                            }
                            timer.cancel()
                        }
                    }
                }
            }, 0, 5000)
        }
    }

    fun verifyPin(pin: String?) {
        isLoading.value = true
        CoroutineScope(Dispatchers.Main).launch {
            tokenResponse = IssueService().processTokenRequest(
                did = did,
                tokenEndPoint = authConfig?.tokenEndpoint,
                code = offerCredential?.grants?.preAuthorizationCode?.preAuthorizedCode,
                codeVerifier = codeVerifier,
                isPreAuthorisedCodeFlow = true,
                userPin = pin
            )
            getCredential()
        }
    }

    fun verifyCredential(url:String){
        CoroutineScope(Dispatchers.Main).launch {
            val presentationRequest =
                VerificationService().processAuthorisationRequest(url)

            val subJwk = DIDService().createJWK()
            val did = DIDService().createDID(subJwk)

            val issuerConfig =
                DiscoveryService().getIssuerConfig(presentationRequest?.clientId)
            val authConfig =
                DiscoveryService().getAuthConfig(issuerConfig?.authorizationServer)

            if (presentationRequest != null) {
                val code = VerificationService().sendVPToken(
                    did = did,
                    subJwk = subJwk,
                    presentationRequest = presentationRequest,
                    credentialList = listOf(credentialJwt.value?:"")
                )
            }
        }
    }
}