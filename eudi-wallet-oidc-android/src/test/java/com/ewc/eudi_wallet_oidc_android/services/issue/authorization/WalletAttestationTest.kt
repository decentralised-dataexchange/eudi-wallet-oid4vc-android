package com.ewc.eudi_wallet_oidc_android.services.issue.authorization

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.Base64

/**
 * ARF TS3 requires the DPoP key to be the one the wallet attestation names in `cnf`.
 *
 * A mismatch is rejected by the authorization server as `invalid_client_attestation`, with nothing
 * in the response saying which of the three possible causes it was — which is why this is worth
 * knowing before the request goes out.
 */
class WalletAttestationTest {

    /** A WIA carrying [key] in `cnf.jwk`. Unsigned: the check reads the payload, it does not verify. */
    private fun attestationNaming(key: ECKey): String {
        val payload = """{"sub":"did:key:zabc","cnf":{"jwk":${key.toPublicJWK().toJSONString()}}}"""
        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.toByteArray())
        return "header.$encoded.signature"
    }

    private fun key() = ECKeyGenerator(Curve.P_256).keyID("k").generate()

    @Test
    fun `the key the attestation names is a match`() {
        val key = key()

        val attestation = WalletAttestation(attestationNaming(key), "pop", key)

        assertEquals(true, attestation.dpopKeyMatchesAttestation)
    }

    @Test
    fun `a different key is not`() {
        val attestation = WalletAttestation(attestationNaming(key()), "pop", key())

        assertEquals(false, attestation.dpopKeyMatchesAttestation)
    }

    /** Null means "nothing to compare", which is not the same as a mismatch. */
    @Test
    fun `nothing to compare reports null rather than false`() {
        assertNull(WalletAttestation(null, null, key()).dpopKeyMatchesAttestation)
        assertNull(WalletAttestation(attestationNaming(key()), "pop", null).dpopKeyMatchesAttestation)
        assertNull(WalletAttestation("not-a-jwt", "pop", key()).dpopKeyMatchesAttestation)
    }

    /** The `~`-terminated SD-JWT form some issuers send must not defeat the lookup. */
    @Test
    fun `a trailing tilde does not defeat the comparison`() {
        val key = key()

        val attestation = WalletAttestation("${attestationNaming(key)}~", "pop", key)

        assertEquals(true, attestation.dpopKeyMatchesAttestation)
    }
}
