package com.ewc.eudiwalletoidcandroid

import android.net.Uri
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedTokenResponse
import com.ewc.eudi_wallet_oidc_android.services.codeVerifier.CodeVerifierService
import com.ewc.eudi_wallet_oidc_android.services.did.DIDService
import com.ewc.eudi_wallet_oidc_android.services.discovery.DiscoveryService
import com.ewc.eudi_wallet_oidc_android.services.issue.IssueService
import com.ewc.eudi_wallet_oidc_android.services.sdjwt.SDJWTService
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationService
import com.google.gson.Gson
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

    var displayText = MutableLiveData<String?>("")

    var credentialJwt = MutableLiveData<String?>("")

    private lateinit var codeVerifier: String
    private var tokenResponse: WrappedTokenResponse? = null
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
                DiscoveryService().getIssuerConfig("${offerCredential?.credentialIssuer}/.well-known/openid-credential-issuer")

            authConfig =
                DiscoveryService().getAuthConfig(
                    "${issuerConfig?.authorizationServer ?: issuerConfig?.issuer}/.well-known/openid-configuration"
                )

            // Generating code verifier
            codeVerifier = CodeVerifierService().generateCodeVerifier()

            withContext(Dispatchers.Main) {
                displayText.value =
                    "${displayText?.value}Issuer Config : \n${Gson().toJson(issuerConfig)}\n\n"
                displayText.value =
                    "${displayText.value}Auth Config : \n${Gson().toJson(authConfig)}\n\n"
                displayText.value =
                    "${displayText.value}Code verifier : \n$codeVerifier\n\n"
            }

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
            tokenResponse?.tokenResponse?.cNonce,
            offerCredential,
            issuerConfig?.credentialEndpoint,
            tokenResponse?.tokenResponse?.accessToken
        )

        withContext(Dispatchers.Main) {
            if (credential?.credentialResponse != null) {
                displayText.value =
                    "${displayText.value}Token : \n${Gson().toJson(tokenResponse)}\n\n"
                displayText.value =
                    "${displayText.value}Credential : \n${Gson().toJson(credential)}\n\n"


                credentialJwt.value = credential.credentialResponse?.credential
                isLoading.value = false
            }
        }

        fetchDeferredCredential(credential?.credentialResponse?.acceptanceToken)
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

                        if (credential?.credentialResponse?.credential != null) {

                            withContext(Dispatchers.Main) {
                                if (credential.credentialResponse?.credential != null) {

                                    displayText.value =
                                        "${displayText.value}Token : \n${Gson().toJson(tokenResponse)}\n\n"
                                    displayText.value =
                                        "${displayText.value}Credential : \n${
                                            Gson().toJson(
                                                credential
                                            )
                                        }\n\n"

                                    credentialJwt.value = credential.credentialResponse?.credential
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

    fun verifyCredential(url: String) {
        CoroutineScope(Dispatchers.Main).launch {
            val presentationRequest =
                VerificationService().processAuthorisationRequest(url)

            val subJwk = DIDService().createJWK()
            val did = DIDService().createDID(subJwk)

            withContext(Dispatchers.Main) {
                displayText.value =
                    "${displayText.value}Verification started\n\n"
                displayText.value =
                    "${displayText.value}Presentation Request : \n${
                        Gson().toJson(
                            presentationRequest
                        )
                    }\n\n"

                displayText.value =
                    "${displayText.value}Did : \n${did}\n\n"

                displayText.value =
                    "${displayText.value}private key : \n${Gson().toJson(subJwk)}\n\n"
            }


            if (presentationRequest != null) {

                val presentationDefinition =
                    VerificationService().processPresentationDefinition(presentationRequest.presentationDefinition)

                val allCredentials = listOf(credentialJwt.value)

                val filteredCredentials = takeFirstElementInEachList(
                    VerificationService().filterCredentials(
                        allCredentials,
                        presentationDefinition
                    ),
                    presentationDefinition.format?.containsKey("sd_jwt") == true,
                    presentationRequest,
                    subJwk
                )

                if (filteredCredentials.isNotEmpty()) {
                    val code = VerificationService().sendVPToken(
                        did = did,
                        subJwk = subJwk,
                        presentationRequest = presentationRequest,
                        credentialList = filteredCredentials
                    )

                    withContext(Dispatchers.Main) {
                        displayText.value =
                            "${displayText.value} ${if (code != null) "Verification success" else "Verification failed"}\n\n"
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        displayText.value =
                            "${displayText.value}No valid credentials\n\n"
                    }
                }
            }
        }
    }

    //since we are doing selection of cards here, we pick the latest card
    private fun takeFirstElementInEachList(
        filterCredentials: List<List<String>>,
        isSdJwt: Boolean,
        presentationRequest: PresentationRequest,
        subJwk: ECKey
    ): List<String> {
        val response: MutableList<String> = mutableListOf()
        filterCredentials.forEach {
            if (it.isNotEmpty())
                if (isSdJwt)
                    response.add(
                        SDJWTService().createSDJWTR(
                            it.first(),
                            presentationRequest,
                            subJwk
                        ) ?: ""
                    )
                else {
                    response.add(it.first())
                }

        }
        return response
    }
}