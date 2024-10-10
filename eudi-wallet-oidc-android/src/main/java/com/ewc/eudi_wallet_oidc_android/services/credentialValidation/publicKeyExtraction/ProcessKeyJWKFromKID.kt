package com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction

import com.ewc.eudi_wallet_oidc_android.services.did.DIDService
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK

class ProcessKeyJWKFromKID {
    /**
     * Processes a JWK from a DID
     *
     * @param did
     * @return
     */

    fun processKeyJWKFromKID(did: String?, algorithm: JWSAlgorithm): JWK? {
        try {
            if (did == null || !did.startsWith("did:key:z")) {
                throw IllegalArgumentException("Invalid DID format")
            }
            // Extract the multiBaseEncoded part
            val multiBaseEncoded = if (did.contains("#")) {
                did.split("#")[0].substring("did:key:z".length)
            } else {
                did.substring("did:key:z".length)
            }
            // Call convertDIDToJWK function from DIDService
            return DIDService().convertDIDToJWK(multiBaseEncoded,algorithm)
        } catch (e: IllegalArgumentException) {
            // Handle specific exception if needed
            throw IllegalArgumentException("Error converting DID to JWK", e)
        } catch (e: Exception) {
            // Handle other exceptions
            throw IllegalArgumentException("Error converting DID to JWK", e)
        }

    }
}