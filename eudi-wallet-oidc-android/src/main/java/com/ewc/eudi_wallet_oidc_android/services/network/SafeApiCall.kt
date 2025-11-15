package com.ewc.eudi_wallet_oidc_android.services.network

import retrofit2.Response
import java.io.IOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import retrofit2.Call
import retrofit2.Callback

object SafeApiCall {
    fun <T> safeApiCallCallback(
        call: Call<T>?,
        onSuccess: (T) -> Unit,
        onError: (String) -> Unit
    ) {
        if (call == null) {
            onError("Service unavailable")
            return
        }

        call.enqueue(object : Callback<T> {
            override fun onResponse(call: Call<T>, response: Response<T>) {
                if (response.isSuccessful || response.code() in 300..399) { // ✅ Handle redirects
                    val body = response.body()
                    if (body != null) {
                        onSuccess(body)
                    } else {
                        onError("Empty response body")
                    }
                } else {
                    // Extract actual error body string
                    val errorMsg = try {
                        response.errorBody()?.string()
                    } catch (e: Exception) {
                        null
                    }

                    val message = errorMsg ?: response.message() ?: "Unknown error"
                    onError(message)
                }
            }

            override fun onFailure(call: Call<T>, t: Throwable) {
                val message = when (t) {
                    is UnknownHostException -> "No Internet or DNS issue"
                    is SocketTimeoutException -> "Connection timed out. Please try again."
                    is IOException -> "Network error occurred. Please check your connection."
                    else -> t.message ?: "Unexpected error occurred"
                }
                onError(message)
            }
        })
    }

    suspend fun <T> safeApiCallResponse(apiCall: suspend () -> Response<T>?): Result<Response<T>> {
        return try {
            val response = apiCall()
            if (response == null) {
                Result.failure(Exception("Service unavailable"))
            } else if (response.isSuccessful || response.code() in 300..399) { // ✅ Consistent with callback
                Result.success(response)
            } else {
                // Extract actual error body string
                val errorMsg = try {
                    response.errorBody()?.string()
                } catch (e: Exception) {
                    null
                }

                val message = errorMsg ?: response.message() ?: "Unknown error"
                Result.failure(Exception(message))
            }
        } catch (e: UnknownHostException) {
            Result.failure(Exception("No Internet or DNS issue"))
        } catch (e: SocketTimeoutException) {
            Result.failure(Exception("Connection timed out. Please try again."))
        } catch (e: IOException) {
            Result.failure(Exception("Network error occurred. Please check your connection."))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

