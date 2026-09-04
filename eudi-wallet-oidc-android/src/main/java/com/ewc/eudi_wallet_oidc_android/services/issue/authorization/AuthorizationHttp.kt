package com.ewc.eudi_wallet_oidc_android.services.issue.authorization

import retrofit2.Response
import java.io.IOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException

/**
 * Performs an authorization-leg request, keeping the response.
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
internal object AuthorizationHttp {

    /**
     * @throws AuthorizationException.RequestFailed when the request never completed.
     */
    suspend fun <T> call(request: suspend () -> Response<T>?): Response<T> = try {
        request() ?: throw AuthorizationException.RequestFailed("Service unavailable")
    } catch (e: UnknownHostException) {
        throw AuthorizationException.RequestFailed("No Internet or DNS issue")
    } catch (e: SocketTimeoutException) {
        throw AuthorizationException.RequestFailed("Connection timed out. Please try again.")
    } catch (e: IOException) {
        throw AuthorizationException.RequestFailed("Network error occurred. Please check your connection.")
    } catch (e: AuthorizationException) {
        throw e
    } catch (e: Exception) {
        throw AuthorizationException.RequestFailed(e.message)
    }

    /**
     * The error body, truncated rather than discarded.
     *
     * This used to return null for anything over [MAX_DETAIL], so a verbose server error yielded
     * *less* information than a terse one and the caller fell back to "the request was refused".
     * A prefix is always more useful than nothing: the OAuth `error` and `error_description` are at
     * the front of any well-formed error body.
     */
    fun errorBody(response: Response<*>): String? = runCatching {
        response.errorBody()?.string()?.takeIf { it.isNotBlank() }?.let { body ->
            if (body.length <= MAX_DETAIL) body else body.take(MAX_DETAIL) + TRUNCATED
        }
    }.getOrNull()

    private const val MAX_DETAIL = 512
    private const val TRUNCATED = "... (truncated)"
}
