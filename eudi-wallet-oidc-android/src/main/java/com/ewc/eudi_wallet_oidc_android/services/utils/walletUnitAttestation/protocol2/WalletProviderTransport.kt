package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.protocol2

import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody

/** An HTTP answer: [code] and [body] are null when no answer came ([failure] says why). */
data class HttpAnswer(
    val code: Int?,
    val body: String?,
    val failure: String? = null
) {
    val isSuccessful: Boolean get() = code != null && code in 200..299
}

/** The HTTP calls of the wallet provider client (a fake in the unit tests). */
interface WalletProviderTransport {
    suspend fun get(url: String): HttpAnswer
    suspend fun post(url: String, headers: Map<String, String>, body: ByteArray): HttpAnswer

    /** The URI exactly as the HTTP client sends it: the `@target-uri` of the signature. */
    fun targetUri(url: String): String = url
}

/** The transport of the SDK: the Retrofit service of [ApiManager]. */
object RetrofitWalletProviderTransport : WalletProviderTransport {

    override suspend fun get(url: String): HttpAnswer = call {
        ApiManager.api.getService()?.fetchNonce(url = url)
    }

    override suspend fun post(url: String, headers: Map<String, String>, body: ByteArray): HttpAnswer {
        // The body media type sets Content-Type; the other headers go as they are.
        val contentType = headers.entries.firstOrNull { it.key.equals(Protocol2Headers.CONTENT_TYPE, true) }?.value
            ?: Protocol2Headers.JSON
        val otherHeaders = headers.filterKeys { !it.equals(Protocol2Headers.CONTENT_TYPE, true) }
        return call {
            ApiManager.api.getService()?.sendSignedRequest(
                url = url,
                headers = otherHeaders,
                body = body.toRequestBody(contentType.toMediaType())
            )
        }
    }

    override fun targetUri(url: String): String = url.toHttpUrlOrNull()?.toString() ?: url

    private suspend fun call(request: suspend () -> retrofit2.Response<okhttp3.ResponseBody>?): HttpAnswer =
        withContext(Dispatchers.IO) {
            try {
                val response = request() ?: return@withContext HttpAnswer(null, null, "Service unavailable")
                val text = try {
                    if (response.isSuccessful) response.body()?.string() else response.errorBody()?.string()
                } catch (e: Exception) {
                    null
                }
                HttpAnswer(response.code(), text)
            } catch (e: Exception) {
                HttpAnswer(null, null, e.message ?: e.javaClass.simpleName)
            }
        }
}
