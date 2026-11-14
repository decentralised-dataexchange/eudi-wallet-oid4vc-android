package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import com.nimbusds.jose.crypto.impl.ECDSA
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.UUID

/**
 * The device key of a wallet unit: the one P-256 key that signs every wallet
 * provider protocol 2 request (RFC 9421) and makes the device signature of
 * the device evidence. The wallet provider finds the unit by the RFC 7638
 * thumbprint of this key, the `keyid` of the signature.
 *
 * iOS has two keys for these jobs (a request key and an App Attest key);
 * Android has one, attested once by its Key Attestation chain, so one file
 * holds it.
 */

/**
 * A key that signs a request: its public JWK, a DER and a raw ECDSA P-256
 * SHA-256 signature (r || s, 64 bytes) over any bytes.
 */
internal interface RequestSigningKey {
    val publicJwk: ECKey

    /** SHA256withECDSA, DER (the device signature header). */
    fun signDer(data: ByteArray): ByteArray

    /** SHA256withECDSA as raw r || s (the `Signature` header). */
    fun signRaw(data: ByteArray): ByteArray = ECDSA.transcodeSignatureToConcat(signDer(data), 64)

    /** The RFC 7638 thumbprint of the public key: the `keyid` of the signature. */
    val keyId: String get() = publicJwk.computeThumbprint().toString()
}

/** A [RequestSigningKey] on a JCA private key (a Keystore key or a software key). */
internal class JcaSigningKey(
    private val privateKey: PrivateKey,
    publicKey: ECPublicKey
) : RequestSigningKey {
    override val publicJwk: ECKey = ECKey.Builder(Curve.P_256, publicKey).build()

    override fun signDer(data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(data)
            sign()
        }
}

/**
 * A device key and its Key Attestation chain (leaf first, standard base64 of
 * each DER certificate). The chain is sent once, at the registration.
 */
internal class DeviceKey(
    val alias: String,
    val signing: RequestSigningKey,
    val x5c: List<String>
)

/**
 * Where the client finds the device key: the Android Keystore in the app, a
 * software key in tests.
 */
internal interface WalletUnitDeviceKeys {
    /** The key of the registered unit, or null when there is none or its entry is gone. */
    fun registered(): DeviceKey?

    /** True when a unit was registered on this install (its alias is stored). */
    val hasRegistration: Boolean

    /**
     * Makes a new device key with [challenge] (the wallet provider nonce) as
     * its attestation challenge. It is not the unit's key until [markRegistered].
     */
    fun make(challenge: String): DeviceKey

    /** The wallet provider registered [key]: it becomes the key of the unit. */
    fun markRegistered(key: DeviceKey)

    /** Deletes a key that was made but not registered. */
    fun discard(key: DeviceKey)

    /** Forgets the registered key: the next WIA request registers a new unit. */
    fun reset()
}

/**
 * [WalletUnitDeviceKeys] in the Android Keystore: StrongBox when the phone has
 * it, else the TEE. The wallet provider refuses a key that was not made in
 * hardware. Only the alias of the registered key is kept, in the SDK's own
 * preferences. If Auto Backup brings the alias back to a new phone, its
 * Keystore entry is not there: that is a lost key, and the app starts a new
 * wallet unit.
 */
internal class KeystoreDeviceKeys(context: Context) : WalletUnitDeviceKeys {

    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    override val hasRegistration: Boolean
        get() = prefs.getString(REGISTERED_ALIAS, null) != null

    override fun registered(): DeviceKey? {
        val alias = prefs.getString(REGISTERED_ALIAS, null) ?: return null
        return load(alias)
    }

    override fun make(challenge: String): DeviceKey {
        val alias = ALIAS_PREFIX + UUID.randomUUID()
        try {
            generate(alias, challenge, strongBox = true)
        } catch (e: StrongBoxUnavailableException) {
            generate(alias, challenge, strongBox = false)
        }
        return load(alias) ?: throw IllegalStateException("The device key was not stored")
    }

    override fun markRegistered(key: DeviceKey) {
        val previous = prefs.getString(REGISTERED_ALIAS, null)
        prefs.edit().putString(REGISTERED_ALIAS, key.alias).apply()
        if (previous != null && previous != key.alias) deleteEntry(previous)
    }

    override fun discard(key: DeviceKey) {
        if (key.alias != prefs.getString(REGISTERED_ALIAS, null)) deleteEntry(key.alias)
    }

    override fun reset() {
        prefs.getString(REGISTERED_ALIAS, null)?.let { deleteEntry(it) }
        prefs.edit().remove(REGISTERED_ALIAS).apply()
    }

    private fun generate(alias: String, challenge: String, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            // The UTF-8 bytes of the nonce string, as the wallet provider checks it.
            .setAttestationChallenge(challenge.toByteArray(Charsets.UTF_8))
            .setIsStrongBoxBacked(strongBox)
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            .apply { initialize(spec) }
            .generateKeyPair()
    }

    private fun load(alias: String): DeviceKey? = try {
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
        val publicKey = entry?.certificate?.publicKey as? ECPublicKey
        if (entry == null || publicKey == null) {
            null
        } else {
            DeviceKey(
                alias = alias,
                signing = JcaSigningKey(entry.privateKey, publicKey),
                x5c = keyStore.getCertificateChain(alias)
                    ?.map { Base64.getEncoder().encodeToString(it.encoded) }
                    ?: emptyList()
            )
        }
    } catch (e: Exception) {
        null
    }

    private fun deleteEntry(alias: String) {
        try {
            keyStore.deleteEntry(alias)
        } catch (e: Exception) {
            // Already gone.
        }
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val PREFS = "eudi_wallet_unit_device_key"
        private const val REGISTERED_ALIAS = "registered_alias"
        private const val ALIAS_PREFIX = "wallet_unit_device_key_"
    }
}
