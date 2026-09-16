package com.ewc.eudi_wallet_oidc_android.services.issue

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
}
