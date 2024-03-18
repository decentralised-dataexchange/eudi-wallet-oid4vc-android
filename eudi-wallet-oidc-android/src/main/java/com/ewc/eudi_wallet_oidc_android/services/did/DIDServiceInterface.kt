package com.ewc.eudi_wallet_oidc_android.services.did

import com.nimbusds.jose.jwk.ECKey

interface DIDServiceInterface {

    /**
     * Generate a did:key:jcs-pub decentralised identifier.
     * @param jwk - DID is created using the JWK
     * @return DID
     */
    fun createDID(jwk: ECKey): String

    /**
     * Generate JWK of curve P-256 for an optional seed value. (ECKey)
     * @param seed is optional, if seed is present then the JWK will be created with the seed
     *          if seed is not present, then will create a new JWK
     *
     * @return JWK
     */
    fun createJWK(seed: String? = null): ECKey
}