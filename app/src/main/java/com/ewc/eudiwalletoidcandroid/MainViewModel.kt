package com.ewc.eudiwalletoidcandroid

import android.content.Context
import android.widget.Toast
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import com.ewc.eudi_wallet_oidc_android.CryptographicAlgorithms
import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.WrappedTokenResponse
import com.ewc.eudi_wallet_oidc_android.services.codeVerifier.CodeVerifierService
import com.ewc.eudi_wallet_oidc_android.services.did.DIDService
import com.ewc.eudi_wallet_oidc_android.services.discovery.DiscoveryService
import com.ewc.eudi_wallet_oidc_android.services.issue.IssueService
import com.ewc.eudi_wallet_oidc_android.services.sdjwt.SDJWTService
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationService
import com.google.gson.Gson
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.ArrayList
import java.util.Timer
import java.util.TimerTask

class MainViewModel : ViewModel() {

    private var format: String? = null
    private var types: ArrayList<String> = arrayListOf()
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
    lateinit var subJwk: JWK

    init {
        isLoading.value = false
    }

    fun issueCredential(url: String,context:Context) {
        isLoading.value = true
        CoroutineScope(Dispatchers.Main).launch {
            // Resolving credential offer
            offerCredential = IssueService().resolveCredentialOffer(url)

            val wrappedResponse = DiscoveryService().getIssuerConfig("${offerCredential?.credentialIssuer}/.well-known/openid-credential-issuer")
            if (wrappedResponse?.issuerConfig != null) {
                // Handle successful response
                issuerConfig = wrappedResponse.issuerConfig
            } else {
                displayErrorMessage(context, wrappedResponse?.errorResponse?.errorDescription)
                return@launch
            }
            val wrappedAuthResponse = DiscoveryService().getAuthConfig(
                "${issuerConfig?.authorizationServer ?: issuerConfig?.issuer}/.well-known/openid-configuration"
            )
            if(wrappedAuthResponse.authConfig !=null){
                // Handle successful response
                authConfig = wrappedAuthResponse.authConfig
            }
            else{
                displayErrorMessage(context, wrappedAuthResponse.errorResponse?.errorDescription)
                return@launch
            }

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
                if (offerCredential?.grants?.preAuthorizationCode?.transactionCode != null) {
                    // pre authorized code flow with pin required
                    isPreAuthorised.value = true
                    isLoading.value = false
                } else {
                    // pre authorized code flow with no pin required
//                    tokenResponse = IssueService().processTokenRequest(
//                        did = did,
//                        tokenEndPoint = authConfig?.tokenEndpoint,
//                        code = offerCredential?.grants?.preAuthorizationCode?.preAuthorizedCode,
//                        codeVerifier = codeVerifier,
//                        isPreAuthorisedCodeFlow = true,
//                        userPin = null
//                    )
                    getCredential()
                }
            } else {
                // Process Authorisation request
//                val authResponse = IssueService().processAuthorisationRequest(
//                    did,
//                    subJwk,
//                    offerCredential,
//                    codeVerifier,
//                    authConfig?.authorizationEndpoint
//                )

//                val code = Uri.parse(authResponse).getQueryParameter("code")

                //process token request
//                tokenResponse = IssueService().processTokenRequest(
//                    did = did,
//                    tokenEndPoint = authConfig?.tokenEndpoint,
//                    code = code,
//                    codeVerifier = codeVerifier,
//                    isPreAuthorisedCodeFlow = false,
//                    userPin = null
//                )
                getCredential()
            }

        }
    }

    private fun displayErrorMessage(context: Context, errorMessage: String?) {
        val messageToShow = errorMessage?.takeIf { it.isNotBlank() } ?: "Unknown error"
        Toast.makeText(context, messageToShow, Toast.LENGTH_SHORT).show()
        isLoading.value = false
    }

    private suspend fun getCredential() {
        val subJwk = DIDService().createJWK()
        val did = DIDService().createDID(subJwk)
        val credential = IssueService().processCredentialRequest(
            did,
            subJwk,
            tokenResponse?.tokenResponse?.cNonce,
            offerCredential,
            issuerConfig,
            tokenResponse?.tokenResponse?.accessToken,
            format ?: "jwt_vc"
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
//            tokenResponse = IssueService().processTokenRequest(
//                did = did,
//                tokenEndPoint = authConfig?.tokenEndpoint,
//                code = offerCredential?.grants?.preAuthorizationCode?.preAuthorizedCode,
//                codeVerifier = codeVerifier,
//                isPreAuthorisedCodeFlow = true,
//                userPin = pin
//            )
            getCredential()
        }
    }

    fun verifyCredential(url: String) {
        CoroutineScope(Dispatchers.Main).launch {
            val presentationRequest =
                VerificationService().processAuthorisationRequest(url)

            val subJwk = DIDService().createJWK(cryptographicAlgorithm = CryptographicAlgorithms.ES256)
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

//                val presentationDefinition =
//                    VerificationService().processPresentationDefinition(presentationRequest.presentationDefinition)
//                val updatedJsonString = "{\"format\":{},\"id\":\"6978f6b6-97be-4918-af02-4625ea49cf20\",\"input_descriptors\":[{\"constraints\":{\"fields\":[{\"filter\":{\"contains\":{\"const\":\"NationalIdCard\"},\"type\":\"string\"},\"path\":[\"\$.vct\"]},{\"path\":[\"\$.name\"]},{\"path\":[\"\$.address\"]},{\"path\":[\"\$.phone.number\"]}],\"limit_disclosure\":\"required\"},\"format\":{\"vc+sd-jwt\":{\"alg\":[\"ES256\"]},\"vp+sd-jwt\":{\"alg\":[\"ES256\"]}},\"id\":\"f945fe99-1185-43ec-8f56-c9684114c9e4\"}]}"
//                val presentationDefinition = Gson().fromJson(
//                    updatedJsonString,
//                    com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition::class.java
//                )

//                val allCredentials = listOf(credentialJwt.value)
                //               val allCredentials = listOf("eyJhbGciOiJFUzI1NiIsImtpZCI6Ii1hZzAxSmNJTjBYOGhNWjV6UE8tVG13N1BMUnRuSWpIZW5MSVRRTnlZUzgiLCJ0eXAiOiJKV1QifQ.eyJfc2QiOlsiRkhpVDYwVW9mZy15UVJ0QjZnSlZNV0d4Nllvb1JVNWNlQXFFUV9YS1VmTSIsInZMem1XalVCSklodjRqdUJvTEQxcU83LVVKelQ3X0ZtMXZWTnRnOXlCcFEiXSwiYWRkcmVzcyI6eyJfc2QiOlsiTFdFb2xJVk4tN2lzSnJjcEF2ZTdzSTVJS0RIYk1JbGtYTTl1UGpIQ2pwVSIsInktVjlrNjd5Mnc2WDJrN0JTWjk2ekZoQVRjUFBibXZDUkhRcU9FbVN1dmciLCJpcENHUUZtQm9UeE1JakE2T1hQeXE1Zlg0ZVg0RTZFQ2ZRZ3d5QVpCVHRVIiwiaUljdkwxalJMbTMzMmgxZ3hYTVlsMkZNTjlHSUZ3M0l1ZENDSG1fYlZ3SSJdfSwiZW1wbG95bWVudCI6eyJkZXNpZ25hdGlvbiI6InRlc3RlciIsInR5cGVPZkVtcGxveW1lbnQiOiJmdWxsIHRpbWUgZW1wbG95ZWUifSwiZXhwIjoxNzMwODc2MzgzLCJpYXQiOjE3MzA3ODk5ODMsImlzcyI6Imh0dHBzOi8vc3RhZ2luZy1vaWQ0dmMuaWdyYW50LmlvL29yZ2FuaXNhdGlvbi8zMGUzMjE5OS02YWIzLTQ1NDMtOTllMC04OWQzYTRkYjU2YmUvc2VydmljZSIsImp0aSI6InVybjpkaWQ6ZWEzYzA1MTgtYzNmMy00OGI0LThjYWYtZWUxN2FlMDdiYmNmIiwibmJmIjoxNzMwNzg5OTgzLCJzdWIiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BnWW95dHlrVVozZXlxaHQxajlLYnJEcnAzUGZWSFJGVUcyOTU5dGZWN3RQeTNqUkdyNXpRaExyam1na2c2N0M2QVozamJ2UWNqMnJlSkZicGhKTGhObUFEYkJCV3IxQ21lSEw1cWZNQ0UzVEJQRmQxUjlZQXZVUGV5VVNQdVJ3RVJOM0YyRnEzTjlzZEhYNlJNeUZmd3oiLCJ2Y3QiOiJOYXRpb25hbElkQ2FyZCJ9.WM9wcchULnOYUrAdpWyl75ua8MC1sA5vqnjGjy85-w7qWYD5bDhhxXM-sGRaCWgQvfapVaTvdlcqH28wChUxGQ~WyI5Y2I3YjdiZmRjNzJiNDczMDhiNzAxNDYxZWEzYTIxOTVhNTIyZjVlMDgwYzQ4NWJkMDIzNGE0MDRmNDBiNjgyIiwiZmllbGQxIiwidGVzdCBmaWVsZDEiXQ~WyJhOGNlYmE1MWE0ZTYxMjhhMjU1OGUzODlkZjRiNWU3MGYxZjcxZGUyZDhhY2U3M2VhZmRhYzQ5ZmZjYWQwNjA5IiwiZmllbGQyIiwidGVzdCBmaWVsZDIiXQ~WyIyMDBlZTExZTUwN2U0OWMxMjgyMDQwNDU1ZjE3MmE3ZGFmNzczNDMwMTQ0MmI3ODdmOGUxNGI4ODMxZWE2NjQ1IiwicGluQ29kZSIsIjY4MDU1NSJd~WyIyMjE1MGNiMGE3NWI5YzA3M2Y2NGFiYTAxYjg4NjQyMzEwYzkwZGFiODhkYjc0NTRhYzJkODJlYTFmN2M0MTNhIiwic3RhdGUiLCJrZXJhbGEiXQ~WyIzOTdkMTVkMGE5NzM1MzY4MTYwZjQ2N2MzOTQ2NDlhMzBmYjNkNzU1ZDQ0ZGFlOWIxZjYwOGFiYzZmZDEzZjUyIiwibmFtZSIsIkxpam8iXQ~WyI1M2Q4NmY1ODQyMGM2MDFmNTYyZWQzNDdlYzU3YzQ4NzM1Nzg1NTliZmQ1MTI4NTJhMzRjOWQ2ZWEzMGYzYjk4IiwicGhvbmUiLHsiY291bnRyeUNvZGUiOiI5MSIsIm51bWJlciI6Ijk3NDU4MDEwNTYifV0")
//                val filteredCredentials = takeFirstElementInEachList(
//                    VerificationService().filterCredentials(
//                        allCredentials,
//                        presentationDefinition
//                    ),
//                    presentationDefinition.format?.containsKey("sd_jwt") == true,
//                    presentationRequest,
//                    subJwk
//                )

                // if (filteredCredentials.isNotEmpty()) {
                val code = presentationRequest.presentationRequest?.let {
                        VerificationService().processAndSendAuthorisationResponse(
                            did = did,
                            subJwk = subJwk,
                            presentationRequest = it,
                            credentialList = listOf("eyJhbGciOiJFUzI1NiIsImtpZCI6Ii1hZzAxSmNJTjBYOGhNWjV6UE8tVG13N1BMUnRuSWpIZW5MSVRRTnlZUzgiLCJ0eXAiOiJKV1QifQ.eyJfc2QiOlsiakZYSGx4U3lfdDFiU0hpRk44Q3U2d1RUNDN3aXBsSzdDTjhueUc5SmF4VSIsImtLb3NxMk1KVWZlZG9HckhaXzlJa1dacUc0SVpvQTREekkyVkdtRjVKRTgiXSwiZXhwIjoxNzM1Nzk4NDAxLCJpYXQiOjE3MzMyMDY0MDEsImlzcyI6Imh0dHBzOi8vc3RhZ2luZy1vaWQ0dmMuaWdyYW50LmlvL29yZ2FuaXNhdGlvbi8zMGUzMjE5OS02YWIzLTQ1NDMtOTllMC04OWQzYTRkYjU2YmUvc2VydmljZSIsImp0aSI6InVybjpkaWQ6YzMxNDYwNmUtNjMyNy00NTJiLTgzOGQtMzllYzg1OTRlOTYxIiwibmJmIjoxNzMzMjA2NDAxLCJzdGF0dXMiOnsic3RhdHVzX2xpc3QiOnsiaWR4IjoxNTA2LCJ1cmkiOiJodHRwczovL3N0YWdpbmctb2lkNHZjLmlncmFudC5pby9vcmdhbmlzYXRpb24vMzBlMzIxOTktNmFiMy00NTQzLTk5ZTAtODlkM2E0ZGI1NmJlL3NlcnZpY2UvcmV2b2NhdGlvbi1zdGF0dXNsaXN0cy8yYmRiNmI4ZS0yZGU3LTQ0ZDYtYjc2NC1mZmZkYmQwNDQ2ZDIifX0sInN1YiI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUtidEEzRkFOWDZ5SHduSkxicWlXNUsxaXhkWEQ0cktCcFJQdG4za29OZm9zZmZWZm1OV3F4akhIVFI5OGhGNVVVd0pXTTNwaUV3eUdYeEVLOUZrWDdocmlqSG5YWE1heFM2R1k2RXdVd1JwNnA2TVZObTlKNGtvb21MaU1ZSll6ODFwRyIsInZjdCI6IkxlZ2FsUGVyc29uYWxJZGVudGlmaWNhdGlvbkRhdGEifQ.nSee2ZHkEaeZGvFVVGm_7Mtj5cnGXYrI1UamtHdvBeC5a5k4PP3FAo1igXCRB3CSzJJ7poMUBo5IXG7lIwAbfQ~WyJiZDhkYjNmMmI1MjUxOGJhMzQ0ZGUxZDNiZjc5MWQyYWM1MGMyODc3Y2M4OGVjMjBiNDU2YTY3YTExZWY4N2ExIiwiaWRlbnRpZmllciIsImRmZCJd~WyIwMDZkMGFmYzJhOGRlYjRhM2RiYjIxNTVlNzdiY2QzMjE0ZGY0ZmE4NDYyZmQ3YzhmZDUxNDA3Y2MxODU4YWNlIiwibGVnYWxOYW1lIiwiZGZkZiJd")
                        )
                }

                withContext(Dispatchers.Main) {
                    displayText.value =
                        "${displayText.value} ${if (code != null) "Verification success" else "Verification failed"}\n\n"
                }
//                } else {
//                    withContext(Dispatchers.Main) {
//                        displayText.value =
//                            "${displayText.value}No valid credentials\n\n"
//                    }
//                }
            }
        }
    }

    //since we are doing selection of cards here, we pick the latest card
    private fun takeFirstElementInEachList(
        filterCredentials: List<List<String>>,
        isSdJwt: Boolean,
        presentationRequest: WrappedPresentationRequest?,
        subJwk: ECKey
    ): List<String> {
        val response: MutableList<String> = mutableListOf()
        filterCredentials.forEach {
            if (it.isNotEmpty())
                if (isSdJwt)
                    response.add(
                        WrappedPresentationRequest(). presentationRequest?.let { it1 ->
                            SDJWTService().createSDJWTR(
                                it.first(),
                                it1,
                                subJwk
                            )
                        } ?: ""
                    )
                else {
                    response.add(it.first())
                }

        }
        return response
    }
}
