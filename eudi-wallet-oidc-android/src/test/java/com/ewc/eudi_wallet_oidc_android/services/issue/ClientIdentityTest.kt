package com.ewc.eudi_wallet_oidc_android.services.issue

import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.Grants
import com.ewc.eudi_wallet_oidc_android.models.PreAuthorizationCode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ClientIdentityTest {

    private val walletId = "did:key:zWalletUnit"

    @Test
    fun `anonymous pre-authorized access has no client identity`() {
        assertNull(ClientIdentity.resolve(true, true, 2, walletId))
    }

    @Test
    fun `pre-authorized without the flag, or with it false, uses the wallet identity`() {
        assertEquals(walletId, ClientIdentity.resolve(true, null, 2, walletId))
        assertEquals(walletId, ClientIdentity.resolve(true, false, 2, walletId))
    }

    @Test
    fun `authorization code always uses the wallet identity`() {
        assertEquals(walletId, ClientIdentity.resolve(false, true, 2, walletId))
    }

    @Test
    fun `pre-1_0 draft pre-authorized offers send no client_id, as before`() {
        assertNull(ClientIdentity.resolve(true, null, 1, walletId))
    }
    private fun preAuthorisedOffer(version: Int) = CredentialOffer(
        grants = Grants(preAuthorizationCode = PreAuthorizationCode(preAuthorizedCode = "code")),
        version = version,
    )

    @Test
    fun `the proof omits iss for an anonymous pre-authorized grant, including after a refresh`() {
        assertNull(ClientIdentity.proofIssuer(preAuthorisedOffer(2), true, walletId, "did:key:zBinding"))
    }

    @Test
    fun `the proof carries the client identity, not the binding DID`() {
        assertEquals(walletId, ClientIdentity.proofIssuer(preAuthorisedOffer(2), null, walletId, "did:key:zBinding"))
        assertEquals(walletId, ClientIdentity.proofIssuer(CredentialOffer(version = 2), true, walletId, "did:key:zBinding"))
    }

    @Test
    fun `the proof keeps the DID for draft pre-authorized offers, or when no client identity is given`() {
        assertEquals("did:key:zBinding", ClientIdentity.proofIssuer(preAuthorisedOffer(1), null, walletId, "did:key:zBinding"))
        assertEquals("did:key:zBinding", ClientIdentity.proofIssuer(CredentialOffer(version = 2), null, null, "did:key:zBinding"))
    }
}
