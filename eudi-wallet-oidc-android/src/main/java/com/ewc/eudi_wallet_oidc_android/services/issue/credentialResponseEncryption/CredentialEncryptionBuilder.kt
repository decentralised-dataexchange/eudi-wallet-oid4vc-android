package com.ewc.eudi_wallet_oidc_android.services.issue.credentialResponseEncryption

import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.CredentialResponsEncryption
import com.ewc.eudi_wallet_oidc_android.models.ECKeyWithAlgEnc
import com.google.gson.JsonParser
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.crypto.ECDHDecrypter

class CredentialEncryptionBuilder {

    fun build(ecKeyWithAlgEnc: ECKeyWithAlgEnc?): CredentialResponsEncryption? {
        try {
            val ecKey = ecKeyWithAlgEnc?.ecKey ?: return null
            val alg = ecKeyWithAlgEnc.alg ?: return null
            val enc = ecKeyWithAlgEnc.enc ?: return null

            val publicJwkJson = JsonParser.parseString(ecKey.toPublicJWK()?.toJSONString())
                .takeIf { it.isJsonObject }
                ?.asJsonObject ?: return null

            return CredentialResponsEncryption(
                jwk = publicJwkJson,
                alg = alg,
                enc = enc
            )
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }


    fun decryptJWE(jwe: String, ecPrivateKey: ECKey?): String? {
        return try {
            if (ecPrivateKey == null) {
                Log.e("decryptJWE", "EC Private Key is null. Cannot decrypt JWE.")
                return null
            }

            val jweObject = JWEObject.parse(jwe)
            jweObject.decrypt(ECDHDecrypter(ecPrivateKey))

            jweObject.payload.toString()
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

}

