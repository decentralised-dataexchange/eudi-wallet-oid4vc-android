package com.ewc.eudi_wallet_oidc_android.services.codeVerifier

interface CodeVerifierServiceInterface {

    /**
     * To generate the code verifier for issuance
     * high-entropy cryptographic random STRING using the
     *    unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
     *    with a minimum length of 43 characters
     *    and a maximum length of 128 characters.
     *    Refer - https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
     * @return code_verifier
     */
    fun generateCodeVerifier(): String?

    /**
     * To generate the code challenge from the code verifier
     * Refer - https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
     * @param codeVerifier
     * @return code_challenge
     */
    fun generateCodeChallenge(codeVerifier: String): String?
}