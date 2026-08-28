package com.ewc.eudi_wallet_oidc_android.services.issue.offer

import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.Credentials
import com.ewc.eudi_wallet_oidc_android.models.Grants
import com.ewc.eudi_wallet_oidc_android.models.PreAuthorizationCode
import com.ewc.eudi_wallet_oidc_android.models.TxCode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** OpenID4VCI 1.0 section 4 conformance. */
class CredentialOfferValidatorTest {

    private val validator = CredentialOfferValidator()

    private fun offer(
        issuer: String? = "https://issuer.example",
        ids: List<String> = listOf("PID"),
        txCode: TxCode? = null,
        preAuthCode: String? = "PRE-1",
    ) = CredentialOffer(
        credentialIssuer = issuer,
        credentials = ArrayList(ids.map { Credentials(types = arrayListOf(it)) }),
        grants = Grants(
            preAuthorizationCode = preAuthCode?.let {
                PreAuthorizationCode(preAuthorizedCode = it, transactionCode = txCode)
            }
        ),
    )

    private fun validate(offer: CredentialOffer, version: CredentialOfferSpecVersion = CredentialOfferSpecVersion.V1_0) =
        validator.validate(offer, version)

    @Test
    fun `a well formed offer passes`() {
        val result = validate(offer())
        assertEquals("https://issuer.example", result.credentialIssuer)
    }

    @Test
    fun `the issuer is trimmed`() {
        assertEquals("https://issuer.example", validate(offer(issuer = "  https://issuer.example  ")).credentialIssuer)
    }

    @Test(expected = CredentialOfferException.Invalid::class)
    fun `a missing issuer is rejected`() {
        validate(offer(issuer = null))
    }

    @Test(expected = CredentialOfferException.Invalid::class)
    fun `a blank issuer is rejected`() {
        validate(offer(issuer = "   "))
    }

    @Test(expected = CredentialOfferException.Invalid::class)
    fun `an issuer that is not an absolute url is rejected`() {
        validate(offer(issuer = "issuer.example"))
    }

    @Test(expected = CredentialOfferException.Invalid::class)
    fun `an offer naming no credentials is rejected`() {
        validate(offer(ids = emptyList()))
    }

    @Test(expected = CredentialOfferException.Invalid::class)
    fun `an offer whose credential names are blank is rejected`() {
        validate(offer(ids = listOf("   ")))
    }

    @Test(expected = CredentialOfferException.Invalid::class)
    fun `duplicate configuration ids are rejected`() {
        // Duplicates would otherwise be requested from the issuer twice.
        validate(offer(ids = listOf("PID", "PID")))
    }

    @Test
    fun `distinct configuration ids are accepted`() {
        assertEquals(2, validate(offer(ids = listOf("PID", "mDL"))).credentials?.size)
    }

    @Test(expected = CredentialOfferException.Invalid::class)
    fun `a pre-authorized grant without a code is rejected`() {
        val broken = offer().apply {
            grants?.preAuthorizationCode = PreAuthorizationCode(preAuthorizedCode = null)
        }
        validate(broken)
    }

    // ── tx_code normalisation ───────────────────────────────────────────────

    @Test
    fun `input_mode defaults to numeric when absent`() {
        val result = validate(offer(txCode = TxCode(length = 4, inputMode = null)))
        assertEquals("numeric", result.grants?.preAuthorizationCode?.transactionCode?.inputMode)
    }

    @Test
    fun `an unrecognised input_mode falls back to numeric rather than failing`() {
        val result = validate(offer(txCode = TxCode(inputMode = "morse")))
        assertEquals("numeric", result.grants?.preAuthorizationCode?.transactionCode?.inputMode)
    }

    @Test
    fun `text input_mode is preserved, case-insensitively`() {
        val result = validate(offer(txCode = TxCode(inputMode = "TEXT")))
        assertEquals("text", result.grants?.preAuthorizationCode?.transactionCode?.inputMode)
    }

    @Test
    fun `an empty tx_code object still requires a code`() {
        val result = validate(offer(txCode = TxCode()))
        val txCode = result.grants?.preAuthorizationCode?.transactionCode
        assertEquals("numeric", txCode?.inputMode)
        assertNull(txCode?.length)
    }

    @Test
    fun `an over-long description is truncated to the 300 character limit`() {
        // Issuer-controlled text rendered directly in the PIN screen.
        val result = validate(offer(txCode = TxCode(description = "x".repeat(400))))
        assertEquals(300, result.grants?.preAuthorizationCode?.transactionCode?.description?.length)
    }

    @Test
    fun `a description within the limit is untouched`() {
        val result = validate(offer(txCode = TxCode(description = "Check your email")))
        assertEquals("Check your email", result.grants?.preAuthorizationCode?.transactionCode?.description)
    }

    @Test
    fun `a non-positive length is discarded`() {
        assertNull(validate(offer(txCode = TxCode(length = 0))).grants?.preAuthorizationCode?.transactionCode?.length)
    }

    // ── draft semantics ─────────────────────────────────────────────────────

    @Test
    fun `draft offers name the credential with the last entry of the type chain`() {
        val draft = CredentialOffer(
            credentialIssuer = "https://issuer.example",
            credentials = arrayListOf(
                Credentials(types = arrayListOf("VerifiableCredential", "PortableDocumentA1"))
            ),
        )
        // Must not throw: the chain's last entry is the credential name.
        validate(draft, CredentialOfferSpecVersion.Draft)
    }

    @Test
    fun `draft offers are not rejected for repeating a type across the chain`() {
        val draft = CredentialOffer(
            credentialIssuer = "https://issuer.example",
            credentials = arrayListOf(
                Credentials(types = arrayListOf("VerifiableCredential", "PID")),
                Credentials(types = arrayListOf("VerifiableCredential", "mDL")),
            ),
        )
        validate(draft, CredentialOfferSpecVersion.Draft)
    }
}
