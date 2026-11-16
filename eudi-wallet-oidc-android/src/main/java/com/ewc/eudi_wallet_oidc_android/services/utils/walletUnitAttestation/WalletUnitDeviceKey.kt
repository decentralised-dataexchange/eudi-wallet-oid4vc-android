package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.ewc.eudi_wallet_oidc_android.logging.Logger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.UUID

/**
 * TEST: the device key of a wallet unit. A P-256 key in the hardware Android
 * Keystore, made at the registration (the first WIA request of the unit) with
 * the wallet provider nonce as its attestation challenge, and kept for the
 * life of the unit. It is not a cnf key: it signs the request binding (the
 * device signature), and its Key Attestation chain goes in the body of the
 * registration only.
 *
 * [isNew] is true for a key made for this request: the request is a
 * registration and carries [x5c].
 */
internal class WalletUnitDeviceKey(
    val alias: String,
    private val privateKey: PrivateKey,
    val x5c: List<String>,
    val isNew: Boolean
) {
    /** SHA256withECDSA (DER) over the UTF-8 request binding, base64url without padding. */
    fun sign(requestBinding: String): String {
        val der = Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(requestBinding.toByteArray(Charsets.UTF_8))
            sign()
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(der)
    }
}

/**
 * TEST: where the device keys live. One registered key per wallet unit: the
 * wallet provider (base URL) and the client_id. A new client_id (the app
 * started a new wallet unit, for example after removing the account) is a new
 * registration with a new key and its chain. Only the alias is stored, in the
 * SDK's preferences; a missing Keystore entry (a new install, a restored
 * backup) also means a new registration.
 */
internal object WalletUnitDeviceKeys {
    private const val TAG = "WalletUnitDeviceKey"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val PREFS = "eudi_wallet_unit_device_key"
    private const val ALIAS_PREFIX = "wallet_unit_device_key_"
    private const val SEPARATOR = " "

    /** The registered key of the wallet unit, or a new key with [nonce] as attestation challenge. */
    fun forRequest(context: Context, baseUrl: String, clientId: String, nonce: String): WalletUnitDeviceKey {
        prefs(context).getString(unit(baseUrl, clientId), null)?.let { alias ->
            load(alias, isNew = false)?.let {
                Logger.d(TAG, "Using the registered device key $alias")
                return it
            }
            Logger.d(TAG, "Registered device key $alias is gone: registering a new wallet unit")
        }
        val alias = ALIAS_PREFIX + UUID.randomUUID()
        generate(alias, nonce)
        val key = load(alias, isNew = true) ?: throw IllegalStateException("The device key was not stored")
        Logger.d(TAG, "New device key $alias, chain of ${key.x5c.size} certificates")
        return key
    }

    /**
     * The wallet provider registered [key]: it becomes the device key of the
     * wallet unit. The keys of earlier wallet units at [baseUrl] are deleted.
     */
    fun markRegistered(context: Context, baseUrl: String, clientId: String, key: WalletUnitDeviceKey) {
        val prefs = prefs(context)
        val current = unit(baseUrl, clientId)
        val editor = prefs.edit()
        prefs.all.forEach { (name, alias) ->
            // Earlier units of this provider, and the entry of the old one-key-per-provider shape.
            if (name != current && (name == baseUrl || name.startsWith("$baseUrl$SEPARATOR"))) {
                (alias as? String)?.takeIf { it != key.alias }?.let { deleteEntry(it) }
                editor.remove(name)
            }
        }
        editor.putString(current, key.alias).apply()
        Logger.d(TAG, "Device key ${key.alias} registered for $clientId at $baseUrl")
    }

    /**
     * The wallet provider refused the registered key of the wallet unit: delete
     * it, so the next request registers a new wallet unit with a new key.
     */
    fun forget(context: Context, baseUrl: String, clientId: String) {
        val prefs = prefs(context)
        val name = unit(baseUrl, clientId)
        prefs.getString(name, null)?.let { deleteEntry(it) }
        prefs.edit().remove(name).apply()
    }

    /** Deletes a key made for a registration that did not succeed. */
    fun discard(key: WalletUnitDeviceKey) {
        if (key.isNew) deleteEntry(key.alias)
    }

    private fun unit(baseUrl: String, clientId: String) = "$baseUrl$SEPARATOR$clientId"

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /**
     * StrongBox when the phone has it, else the TEE; device properties in the
     * attestation on Android 12 and later when the Keystore allows it.
     */
    private fun generate(alias: String, nonce: String) {
        val withProperties = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
        val attempts = listOf(true to withProperties, true to false, false to withProperties, false to false)
            .distinct()
        var last: Exception? = null
        for ((strongBox, properties) in attempts) {
            try {
                val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    // The nonce of the WIA request, not the request binding.
                    .setAttestationChallenge(nonce.toByteArray(Charsets.UTF_8))
                    .apply { if (strongBox) setIsStrongBoxBacked(true) }
                    .apply {
                        if (properties && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                            setDevicePropertiesAttestationIncluded(true)
                        }
                    }
                    .build()
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
                    .apply { initialize(spec) }
                    .generateKeyPair()
                Logger.d(TAG, "Device key made (strongBox=$strongBox, deviceProperties=$properties)")
                return
            } catch (e: Exception) {
                Logger.d(TAG, "Device key not made (strongBox=$strongBox, deviceProperties=$properties): ${e.javaClass.simpleName}")
                deleteEntry(alias)
                last = e
            }
        }
        throw IllegalStateException("No hardware device key could be made", last)
    }

    private fun load(alias: String, isNew: Boolean): WalletUnitDeviceKey? = try {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
        entry?.let {
            WalletUnitDeviceKey(
                alias = alias,
                privateKey = it.privateKey,
                // Standard base64 of each DER certificate, leaf first.
                x5c = keyStore.getCertificateChain(alias)
                    ?.map { cert -> Base64.getEncoder().encodeToString(cert.encoded) }
                    ?: emptyList(),
                isNew = isNew
            )
        }
    } catch (e: Exception) {
        null
    }

    private fun deleteEntry(alias: String) {
        try {
            KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.deleteEntry(alias)
        } catch (e: Exception) {
            // Already gone.
        }
    }
}
