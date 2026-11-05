package com.ewc.eudi_wallet_oidc_android.services.network

/**
 * A non-2xx answer that [SafeApiCall.safeApiCallResponse] turned into a failure.
 *
 * The message is the response body exactly as before, so nothing reading `message` changes. The
 * status and the `X-Request-Id` header, which that conversion used to throw away, ride along so
 * the error built from it can still say what happened and which request it was.
 */
internal class HttpErrorException(
    val status: Int,
    val requestId: String?,
    message: String?,
) : Exception(message)
