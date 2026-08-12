package com.ewc.eudi_wallet_oidc_android.services.network

import com.google.gson.GsonBuilder
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import javax.security.cert.CertificateException

object ApiManager {

    private const val BASE_URL = "https://api.example.com/"

    private var okClient: OkHttpClient? = null
    private var service: ApiService? = null
    private var httpClient: OkHttpClient.Builder? = null

    private var apiManager: ApiManager? = null

    /** Kept so [setNetworkLoggingEnabled] works whether it is called before or after first use. */
    private val httpLoggingInterceptor = HttpLoggingInterceptor().apply {
        level = HttpLoggingInterceptor.Level.NONE
    }

    /**
     * Full request/response logging. **Off by default** — the traffic on this client carries
     * credentials, access and refresh tokens and PID attributes, and `Level.BODY` writes all of it
     * to logcat, readable by anything with `READ_LOGS` or adb. It also buffers every response body
     * into memory and copies it to a String, which on large issuer metadata is megabytes of heap
     * per request.
     *
     * A library's own `BuildConfig.DEBUG` is false in a published AAR regardless of the host's
     * build type, so this is an explicit opt-in rather than an automatic debug check. Host apps
     * should enable it only in debug builds.
     */
    fun setNetworkLoggingEnabled(enabled: Boolean) {
        httpLoggingInterceptor.level =
            if (enabled) HttpLoggingInterceptor.Level.BODY else HttpLoggingInterceptor.Level.NONE
    }

    fun getService(): ApiService? {
        return service
    }

    val api: ApiManager
        get() {
            if (apiManager == null) {
                apiManager = ApiManager
                httpClient = OkHttpClient.Builder()
                httpClient?.followRedirects(false)
                httpClient!!.addInterceptor(httpLoggingInterceptor)
                okClient = httpClient!!.readTimeout(120, TimeUnit.SECONDS)
                    .connectTimeout(120, TimeUnit.SECONDS).build()
                val gson = GsonBuilder()
                    .setLenient()
                    .create()
                val retrofit = Retrofit.Builder()
                    .baseUrl(BASE_URL)
                    .client(okClient!!)
                    .addConverterFactory(GsonConverterFactory.create(gson))
                    .build()
                service = retrofit.create(ApiService::class.java)
            }
            return apiManager!!
        }
}