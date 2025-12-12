package com.ewc.eudi_wallet_oidc_android.services.verification.mdoc

import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import com.ewc.eudi_wallet_oidc_android.models.DeviceSigned
import com.nimbusds.jose.jwk.JWK

fun createDeviceSigned(jwk: JWK?, sessionTranscriptCbor: ByteArray): DeviceSigned {
    val emptyNamespaces = createTaggedEmptyNamespaces()

    if (jwk!=null) {
        val ecJwk = jwk.toECKey()
        val privateKey = ecJwk.toPrivateKey()

        val deviceSignature = createDeviceSignedCose(privateKey, sessionTranscriptCbor)

        val deviceAuth = Map().apply {
            put(UnicodeString("deviceSignature"), deviceSignature)
        }
        return DeviceSigned(emptyNamespaces, deviceAuth)
    } else {
        return DeviceSigned(emptyNamespaces,Map())
    }
}
