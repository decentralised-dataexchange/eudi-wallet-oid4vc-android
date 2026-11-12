package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.protocol2

/**
 * The headers of a protocol 2 request of the wallet provider (CONTRACT.md section 2): the JSON
 * body headers, the statements of the app, and the RFC 9421 signature of the request key.
 */
object Protocol2Headers {

    const val CONTENT_TYPE = "Content-Type"
    const val CONTENT_DIGEST = "Content-Digest"
    const val NONCE = "X-Wallet-Unit-Nonce"
    const val PLATFORM = "X-Wallet-Unit-Platform"
    const val APP_VERSION = "X-Wallet-App-Version"
    const val APP_BUILD = "X-Wallet-App-Build"
    const val DEVICE_MODEL = "X-Wallet-Device-Model"
    const val INTEGRITY_TOKEN = "X-Wallet-Unit-Integrity-Token"
    const val DEVICE_SIGNATURE = "X-Wallet-Unit-Device-Signature"
    const val SIGNATURE_INPUT = "Signature-Input"
    const val SIGNATURE = "Signature"

    const val JSON = "application/json"

    /** The covered components of an Android request, in the order of the contract. */
    val ANDROID_COMPONENTS: List<String> = listOf(
        "@method",
        "@target-uri",
        "content-digest",
        "x-wallet-unit-nonce",
        "x-wallet-unit-platform",
        "x-wallet-app-version",
        "x-wallet-app-build",
        "x-wallet-device-model"
    )

    /**
     * All headers of a signed POST to [targetUri] with [body]. [nonce] is the wallet provider
     * nonce (for the key attestation route: the issuer `c_nonce`). [created] is in unix seconds.
     */
    fun signedPost(
        targetUri: String,
        body: ByteArray,
        nonce: String,
        app: WalletAppIdentity,
        requestKey: WalletUnitRequestKey,
        created: Long
    ): Map<String, String> = sign("POST", targetUri, body, nonce, app, requestKey, created).first

    /** As [signedPost], also with the signature base (tests and diagnostics). */
    fun sign(
        method: String,
        targetUri: String,
        body: ByteArray,
        nonce: String,
        app: WalletAppIdentity,
        requestKey: WalletUnitRequestKey,
        created: Long
    ): Pair<Map<String, String>, HttpMessageSignature.Signed> {
        val headers = linkedMapOf(
            CONTENT_TYPE to JSON,
            CONTENT_DIGEST to ContentDigest.sha256(body),
            NONCE to nonce,
            PLATFORM to app.platform,
            APP_VERSION to app.version,
            APP_BUILD to app.build,
            DEVICE_MODEL to app.deviceModel
        )
        val signed = HttpMessageSignature.sign(
            method = method,
            targetUri = targetUri,
            headers = headers,
            components = ANDROID_COMPONENTS,
            created = created,
            keyId = requestKey.keyId,
            signDer = requestKey::signDer
        )
        headers[SIGNATURE_INPUT] = signed.signatureInput
        headers[SIGNATURE] = signed.signature
        return headers to signed
    }
}
