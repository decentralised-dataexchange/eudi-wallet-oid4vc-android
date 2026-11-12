package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.protocol2

import android.os.Build

/**
 * What a protocol 2 request states about the app (CONTRACT.md section 2): `X-Wallet-App-Version`
 * (the dotted version name), `X-Wallet-App-Build` (the decimal version code) and, on Android,
 * `X-Wallet-Device-Model` (`Build.MANUFACTURER + " " + Build.MODEL`).
 */
data class WalletAppIdentity(
    val version: String,
    val build: String,
    val deviceModel: String,
    val platform: String = PLATFORM_ANDROID
) {
    companion object {
        const val PLATFORM_ANDROID = "android"

        /** The identity of this app on this device: pass `BuildConfig.VERSION_NAME` and `VERSION_CODE`. */
        fun of(versionName: String, versionCode: Long): WalletAppIdentity =
            WalletAppIdentity(
                version = versionName,
                build = versionCode.toString(),
                deviceModel = "${Build.MANUFACTURER} ${Build.MODEL}"
            )
    }
}

/**
 * The device evidence of a request: a classic Play Integrity token whose nonce is the request
 * binding. Null when the device cannot give one (no Play services, a refusal of Google Play).
 */
fun interface IntegrityTokenSource {
    suspend fun token(requestBinding: String): String?
}
