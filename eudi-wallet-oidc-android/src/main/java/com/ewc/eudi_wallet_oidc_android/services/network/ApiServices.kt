package com.ewc.eudi_wallet_oidc_android.services.network

import com.ewc.eudi_wallet_oidc_android.CredentialOfferResponse
import com.ewc.eudi_wallet_oidc_android.models.RefreshTokenResponse
import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.ClientAssertion
import com.ewc.eudi_wallet_oidc_android.models.CredentialRequest
import com.ewc.eudi_wallet_oidc_android.models.CredentialResponse
import com.ewc.eudi_wallet_oidc_android.models.DIDDocument
import com.ewc.eudi_wallet_oidc_android.models.NotificationRequest
import com.ewc.eudi_wallet_oidc_android.models.ParResponse
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import com.ewc.eudi_wallet_oidc_android.models.v2.DeferredCredentialRequestV2
import okhttp3.ResponseBody
import retrofit2.Call
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.Field
import retrofit2.http.FieldMap
import retrofit2.http.FormUrlEncoded
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.HeaderMap
import retrofit2.http.POST
import retrofit2.http.QueryMap
import retrofit2.http.Url
//import retrofit2.Call

interface ApiService {
    @GET
    suspend fun resolveCredentialOffer(@Url url: String): Response<ResponseBody>

    @GET
    suspend fun fetchIssuerConfig(@Url url: String): Response<ResponseBody>

    @GET
    suspend fun fetchAuthConfig(@Url url: String): Response<AuthorisationServerWellKnownConfiguration>

    @GET
    suspend fun processAuthorisationRequest(
        @Url url: String,
        @QueryMap map: Map<String, String>
    ): Response<ResponseBody>

    @FormUrlEncoded
    @POST
    suspend fun processParAuthorisationRequest(
        @Url url: String,
        @FieldMap map: Map<String, String>
    ): Response<ParResponse>

    @FormUrlEncoded
    @POST("")
    suspend fun sendIdTokenForCode(
        @Url url: String,
        @Field("id_token") idToken: String,
        @Field("state") state: String,
        @Header("content-type") contentType: String
    ): Response<HashMap<String, Any>>

    @FormUrlEncoded
    @POST("")
    suspend fun getAccessTokenFromCode(
        @Url url: String,
        @FieldMap map: Map<String, String?>,
        @HeaderMap headers: Map<String, String> = emptyMap()
    ): Response<TokenResponse>

    @POST
    suspend fun getCredential(
        @Url url: String,
        @Header("content-type") contentType: String,
        @Header("Authorization") authorization: String,
        @Body body: CredentialRequest
    ): Response<ResponseBody>

    @POST("")
    suspend fun getDifferedCredential(
        @Url url: String,
        @Header("Authorization") authorization: String,
        @Body body: CredentialRequest
    ): Response<ResponseBody>
    @POST("")
    suspend fun getDifferedCredentialV2(
        @Url url: String,
        @Header("Authorization") authorization: String,
        @Body body: DeferredCredentialRequestV2
    ): Response<ResponseBody>

    @GET
    suspend fun getPresentationDefinitionFromRequestUri(@Url url: String): Response<ResponseBody>

    @GET
    suspend fun resolveUrl(@Url url: String): Response<ResponseBody>

    @FormUrlEncoded
    @POST("")
    suspend fun sendVPToken(
        @Url url: String,
        @FieldMap map: Map<String, String>,
        @HeaderMap headers: Map<String, String> = emptyMap()
    ): Response<ResponseBody>

    @GET
    suspend fun ebsiDIDResolver(@Url url: String): Response<DIDDocument>
    @GET
    fun getStatusList(
        @Url url: String, // Dynamically set the URL
        @Header("Accept") accept: String // Dynamically set the Accept header
    ): Call<ResponseBody>

    @POST
    suspend fun sendWUARequest(
        @Url url: String,
        @Header("X-Wallet-Unit-Integrity-Token") deviceIntegrityToken: String,
        @Header("X-Wallet-Unit-Platform") devicePlatform: String,
        @Header("X-Wallet-Unit-Nonce") nonce: String,
        @Body body: ClientAssertion
    ): Response<CredentialOfferResponse>

    @GET
    suspend fun fetchNonce(@Url url: String): Response<ResponseBody>

    @FormUrlEncoded
    @POST("")
    suspend fun getRefreshTokenFromCode(
        @Url url: String,
        @FieldMap map: Map<String, String?>,
        // @HeaderMap headers: Map<String, String> = emptyMap()
    ): Response<RefreshTokenResponse>
    @POST("")
    suspend fun sendNotificationRequest(
        @Url url: String,
        @Header("Authorization") authorization: String,
        @Body body: NotificationRequest
    ): Response<ResponseBody>
    @GET
    fun getVerifiableCredentialStatusList(
        @Url url: String, // Dynamically set the URL
    ): Call<ResponseBody>
    @POST
    suspend fun fetchNonce(
        @Url url: String,
        @Header("Authorization") authorization: String?=null,
    ): Response<ResponseBody>

    @GET
    suspend fun getTrustServiceProviders(
        @Url url: String // Dynamically set the URL
    ): Response<ResponseBody>
}
