package com.ewc.eudi_wallet_oidc_android.services.verification.mdoc

import android.util.Log
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import com.ewc.eudi_wallet_oidc_android.models.DeviceSigned
import com.nimbusds.jose.jwk.JWK
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

fun ByteArray.toHex(): String =
    joinToString("") { "%02x".format(it) }

fun createDeviceSigned(jwk: JWK?, sessionTranscriptCbor: Array): DeviceSigned {

    Log.d("Device signing", "▶ createDeviceSigned() called")
//    Log.d("Device signing","SessionTranscript CBOR (hex): ${sessionTranscriptCbor.toHex()}")

    val emptyNamespaces = createTaggedEmptyNamespaces()
    Log.d("Device signing","Empty namespaces (tagged CBOR): $emptyNamespaces")

    if (jwk!=null) {
        Log.d("Device signing", "JWK provided, creating DeviceSignature")


        val ecJwk = jwk.toECKey()

        // ---- Public Key ----
        val publicKey = ecJwk.toPublicKey() as ECPublicKey
        val publicKeyEncoded = publicKey.encoded
        Log.d("Device signing", "Public Key (X.509 DER, hex): ${publicKeyEncoded.toHex()}")


        // ---- Private Key ----
        val privateKey = ecJwk.toPrivateKey() as ECPrivateKey
        val privateKeyEncoded = privateKey.encoded
        Log.d("Device signing", "Private Key (PKCS#8 DER, hex): ${privateKeyEncoded.toHex()}")

        val deviceSignature = createDeviceSignedCose(privateKey, sessionTranscriptCbor, emptyNamespaces)


        val deviceAuth = Map().apply {
            put(UnicodeString("deviceSignature"), deviceSignature)
        }
        return DeviceSigned(emptyNamespaces, deviceAuth)
    } else {
        return DeviceSigned(emptyNamespaces,Map())
    }
}
