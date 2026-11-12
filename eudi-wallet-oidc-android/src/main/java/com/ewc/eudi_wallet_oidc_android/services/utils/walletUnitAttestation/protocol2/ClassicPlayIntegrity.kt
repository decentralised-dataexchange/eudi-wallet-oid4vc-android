package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.protocol2

import android.content.Context
import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/**
 * Classic Play Integrity (`IntegrityManager.requestIntegrityToken`), owner decision D5: the wallet
 * provider decrypts and verifies the token locally with the keys of its app record, with no call
 * to Google. The nonce is the request binding ([RequestBinding]), base64url without padding; the
 * wallet provider compares `requestDetails.nonce` with it after a base64url decode.
 *
 * A failure gives null (the caller decides: a WIA request cannot go without evidence, a status
 * request can).
 */
class ClassicPlayIntegrity(
    context: Context,
    private val cloudProjectNumber: Long
) : IntegrityTokenSource {

    private val appContext = context.applicationContext

    override suspend fun token(requestBinding: String): String? =
        suspendCancellableCoroutine { cont ->
            try {
                val request = IntegrityTokenRequest.builder()
                    .setNonce(requestBinding)
                    .setCloudProjectNumber(cloudProjectNumber)
                    .build()
                IntegrityManagerFactory.create(appContext)
                    .requestIntegrityToken(request)
                    .addOnSuccessListener { response -> if (cont.isActive) cont.resume(response.token()) }
                    .addOnFailureListener { e ->
                        Logger.e(TAG, "Classic Play Integrity request failed: ${e.message}")
                        if (cont.isActive) cont.resume(null)
                    }
            } catch (e: Exception) {
                Logger.e(TAG, "Classic Play Integrity request failed: ${e.message}")
                if (cont.isActive) cont.resume(null)
            }
        }

    private companion object {
        const val TAG = "ClassicPlayIntegrity"
    }
}
