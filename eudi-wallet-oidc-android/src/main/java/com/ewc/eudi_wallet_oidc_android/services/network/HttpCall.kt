package com.ewc.eudi_wallet_oidc_android.services.network

import retrofit2.Response
import java.io.IOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException

/**
 * Performs a request, keeping the status code and the headers.
 *
 * Deliberately not routed through
 * [com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall]: that helper converts any non-2xx
 * into a failure carrying only the response body, discarding the status code and every header.
 *
 * That mattered here. The previous implementation logged a rejected PAR together with the server's
 * `Date` header, specifically so a rejection could be compared against the proof-of-possession
 * `iat` when it looked like clock skew — but because SafeApiCall had already turned the 400 into a
 * failure, that branch could only ever be reached for a 3xx. The diagnostics never fired for the
 * case they were written for.
 *
 * The transport-exception messages below are kept identical to SafeApiCall's, so nothing a user
 * sees changes wording.
 */
internal object HttpCall {

    /**
     * Performs [request] and hands back the whole response.
     *
     * @param onTransportFailure builds the exception thrown when the request never completed, so
     *   each leg can raise its own type. The messages are the ones SafeApiCall uses, so nothing a
     *   user sees changes wording.
     */
    suspend fun <T> call(
        onTransportFailure: (String?) -> Exception,
        request: suspend () -> Response<T>?,
    ): Response<T> {
        // The null check is deliberately outside the try: raising it inside would let the catch
        // below wrap our own exception a second time.
        val response = try {
            request()
        } catch (e: UnknownHostException) {
            throw onTransportFailure("No Internet or DNS issue")
        } catch (e: SocketTimeoutException) {
            throw onTransportFailure("Connection timed out. Please try again.")
        } catch (e: IOException) {
            throw onTransportFailure("Network error occurred. Please check your connection.")
        } catch (e: Exception) {
            throw onTransportFailure(e.message)
        }
        return response ?: throw onTransportFailure("Service unavailable")
    }

    /**
     * The whole error body, or null when there is none.
     *
     * Whole, because it is parsed next: RFC 6749 section 5.2 makes the body a JSON object, and
     * cutting it first turned any body over a few hundred characters into unparsable text, which
     * lost the `error` code and with it every retry keyed on one. Cut it with [summary] only where
     * it is logged or shown.
     */
    fun errorBody(response: Response<*>): String? = runCatching {
        response.errorBody()?.string()?.takeIf { it.isNotBlank() }
    }.getOrNull()

    /** [body] cut down for a log line or a user-facing fallback. Parse the whole body first. */
    fun summary(body: String?): String? = body?.let {
        if (it.length <= MAX_DETAIL) it else it.take(MAX_DETAIL) + TRUNCATED
    }

    private const val MAX_DETAIL = 512
    private const val TRUNCATED = "... (truncated)"
}
