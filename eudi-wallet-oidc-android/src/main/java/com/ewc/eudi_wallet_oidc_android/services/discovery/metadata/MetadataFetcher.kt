package com.ewc.eudi_wallet_oidc_android.services.discovery.metadata

import com.ewc.eudi_wallet_oidc_android.services.UriValidationFailed
import com.ewc.eudi_wallet_oidc_android.services.UrlUtils
import okhttp3.ResponseBody
import retrofit2.Response
import java.io.IOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.Locale

/** A retrieved metadata document and the response metadata needed to interpret it. */
internal data class MetadataDocument(
    val url: String,
    val body: String,
    val contentType: String?,
) {
    val isJwtMediaType: Boolean
        get() = contentType?.substringBefore(';')?.trim()?.lowercase() == MEDIA_TYPE_JWT

    val isJsonMediaType: Boolean
        get() = contentType?.substringBefore(';')?.trim()?.lowercase()
            ?.let { it == MEDIA_TYPE_JSON || it.endsWith("+json") } == true

    companion object {
        const val MEDIA_TYPE_JSON = "application/json"
        const val MEDIA_TYPE_JWT = "application/jwt"
    }
}

/**
 * Retrieves a metadata document over HTTP.
 *
 * Deliberately does **not** route through
 * [com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall]: that helper converts any
 * non-2xx into a `Result.failure` carrying only the response body, discarding the status code. The
 * status is exactly what discovery needs, because trying several well-known URLs means deciding
 * which of several failures to report, and "404 on the URL we tried last" is a far worse message
 * than "403 on the URL the issuer actually uses". The transport-exception messages below are kept
 * identical to SafeApiCall's so nothing the user sees changes wording.
 */
internal object MetadataFetcher {

    /** The `Accept` header to send, given whether the wallet can verify a signature. */
    fun acceptHeader(supportsSignedMetadata: Boolean): String =
        if (supportsSignedMetadata) {
            "${MetadataDocument.MEDIA_TYPE_JSON}, ${MetadataDocument.MEDIA_TYPE_JWT}"
        } else {
            // Section 12.2.2 treats Accept as "signaling whether it supports signed metadata", so a
            // wallet that cannot verify one must not ask for it.
            MetadataDocument.MEDIA_TYPE_JSON
        }

    /** The `Accept-Language` header to send, or null when the policy disables it. */
    fun acceptLanguageHeader(policy: DiscoveryPolicy): String? {
        if (!policy.sendAcceptLanguage) return null
        policy.acceptLanguage?.takeIf { it.isNotBlank() }?.let { return it }
        return try {
            Locale.getDefault().toLanguageTag().takeIf { it.isNotBlank() && it != "und" }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * @param call performs the request. Supplied by the caller so issuer and authorization server
     *   lookups can use their own Retrofit methods while sharing this handling.
     * @throws DiscoveryException
     */
    suspend fun fetch(
        url: String,
        policy: DiscoveryPolicy,
        call: suspend (String) -> Response<ResponseBody>?,
    ): MetadataDocument {
        try {
            UrlUtils.validateUri(url)
        } catch (e: UriValidationFailed) {
            throw DiscoveryException.InvalidIdentifier(url)
        }

        val response = try {
            call(url)
        } catch (e: UnknownHostException) {
            throw DiscoveryException.FetchFailed(null, "No Internet or DNS issue")
        } catch (e: SocketTimeoutException) {
            throw DiscoveryException.FetchFailed(null, "Connection timed out. Please try again.")
        } catch (e: SecurityException) {
            throw DiscoveryException.FetchFailed(null, e.message)
        } catch (e: IOException) {
            val message = if (e is javax.net.ssl.SSLHandshakeException) {
                "Unable to establish a secure connection."
            } else {
                "Network error occurred. Please check your connection."
            }
            throw DiscoveryException.FetchFailed(null, message)
        } catch (e: Exception) {
            throw DiscoveryException.FetchFailed(null, e.message)
        } ?: throw DiscoveryException.FetchFailed(null, "Service unavailable")

        if (!response.isSuccessful) {
            val detail = try {
                response.errorBody()?.string()?.takeIf { it.isNotBlank() && it.length <= MAX_DETAIL }
            } catch (e: Exception) {
                null
            }
            throw DiscoveryException.FetchFailed(
                response.code(),
                detail ?: response.message().takeIf { it.isNotBlank() },
            )
        }

        val contentType = response.headers()["Content-Type"]
        val body = response.body()
        val declaredLength = body?.contentLength() ?: -1L
        policy.maxMetadataBytes?.let { limit ->
            if (declaredLength > limit) {
                throw DiscoveryException.TooLarge(declaredLength)
            }
        }

        val text = try {
            body?.string().orEmpty()
        } catch (e: Exception) {
            throw DiscoveryException.FetchFailed(response.code(), "The issuer configuration could not be read")
        }
        policy.maxMetadataBytes?.let { limit ->
            if (text.length > limit) {
                throw DiscoveryException.TooLarge(text.length.toLong())
            }
        }
        if (text.isBlank()) {
            throw DiscoveryException.FetchFailed(response.code(), "The issuer configuration was empty")
        }

        return MetadataDocument(url = url, body = text, contentType = contentType)
    }

    /**
     * True when [text] is shaped like a compact JWS.
     *
     * Checked in addition to the media type, because a document served as `application/json` that
     * is in fact a JWT must still reach the verifier rather than be silently trusted.
     */
    fun looksLikeJwt(text: String): Boolean {
        val trimmed = text.trim()
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) return false
        val parts = trimmed.split('.')
        if (parts.size != 3) return false
        return parts.take(2).all { part ->
            part.isNotEmpty() && part.all { it.isLetterOrDigit() || it == '-' || it == '_' || it == '=' }
        }
    }

    private const val MAX_DETAIL = 512
}