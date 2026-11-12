package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.protocol2

import com.nimbusds.jose.jwk.ECKey
import java.security.PrivateKey
import java.security.Signature

/**
 * The request key of a wallet unit (CONTRACT.md section 2): on Android the device key, an EC P-256
 * key in the Android Keystore (hardware, StrongBox when the device has one). It signs every
 * protocol 2 request (RFC 9421) and the device signature over the request binding. The wallet
 * provider finds the unit by its RFC 7638 thumbprint (`keyid`).
 */
interface WalletUnitRequestKey {
    /** The public JWK (EC P-256). */
    val publicJwk: ECKey

    /** The DER ECDSA P-256 SHA-256 signature of [data]. */
    fun signDer(data: ByteArray): ByteArray

    /** The RFC 7638 thumbprint of [publicJwk], base64url: the `keyid` of the signature. */
    val keyId: String
        get() = publicJwk.toPublicJWK().computeThumbprint().toString()
}

/** A request key made at a registration, with its Android Key Attestation chain (base64 DER, leaf first). */
class AttestedRequestKey(
    val key: WalletUnitRequestKey,
    val x5c: List<String>
)

/**
 * The store of the request key of the wallet unit. The app gives the Android Keystore
 * implementation: one key for each wallet unit, made at the registration with the nonce of the
 * wallet provider as attestation challenge.
 */
interface WalletUnitRequestKeyStore {
    /** The request key that the wallet provider registered, or null before the registration. */
    fun registeredKey(): WalletUnitRequestKey?

    /** Makes a new key with [challenge] as attestation challenge. Null when the Keystore refuses. */
    fun newAttestedKey(challenge: ByteArray): AttestedRequestKey?

    /** The registration with [key] succeeded: it is the registered key from now on. */
    fun markRegistered(key: AttestedRequestKey)

    /** The registration with [key] failed: delete it. */
    fun discard(key: AttestedRequestKey)

    /** The wallet provider does not know the registered key: delete it; the next WIA request registers a new one. */
    fun forgetRegistered()
}

/** A request key with a private key object: a Keystore handle, or a software key (tests). */
class PrivateKeyRequestKey(
    override val publicJwk: ECKey,
    private val privateKey: PrivateKey
) : WalletUnitRequestKey {

    override fun signDer(data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(data)
            sign()
        }

    companion object {
        /** From an EC JWK with its private part (software key). */
        fun of(ecKey: ECKey): PrivateKeyRequestKey =
            PrivateKeyRequestKey(ecKey.toPublicJWK(), ecKey.toPrivateKey())
    }
}
