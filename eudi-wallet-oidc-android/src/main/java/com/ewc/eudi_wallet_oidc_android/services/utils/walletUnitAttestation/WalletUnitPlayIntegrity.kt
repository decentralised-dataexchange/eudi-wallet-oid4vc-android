package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * The Play Integrity token of the device evidence of a protocol 2 request.
 * The app uses [ClassicPlayIntegrity]; tests use a fake.
 */
internal interface WalletUnitIntegrity {
    /** A token whose nonce is [binding], the request binding of the request. */
    suspend fun token(binding: String): String
}

/**
 * A **classic** Play Integrity token (`IntegrityManager.requestIntegrityToken`,
 * not the Standard API) with nonce = the request binding. The wallet provider
 * decrypts it with the keys of the app record and compares the nonce as text.
 * The binding is 43 base64url characters, a valid classic nonce.
 *
 * Each token counts against the daily Play Integrity quota of the app.
 */
internal class ClassicPlayIntegrity(
    context: Context,
    private val cloudProjectNumber: Long
) : WalletUnitIntegrity {

    private val manager = IntegrityManagerFactory.create(context.applicationContext)

    override suspend fun token(binding: String): String = suspendCancellableCoroutine { cont ->
        try {
            manager.requestIntegrityToken(
                IntegrityTokenRequest.builder()
                    .setNonce(binding)
                    .setCloudProjectNumber(cloudProjectNumber)
                    .build()
            )
                .addOnSuccessListener { response -> if (cont.isActive) cont.resume(response.token()) }
                .addOnFailureListener { e -> if (cont.isActive) cont.resumeWithException(e) }
        } catch (e: Exception) {
            if (cont.isActive) cont.resumeWithException(e)
        }
    }
}
