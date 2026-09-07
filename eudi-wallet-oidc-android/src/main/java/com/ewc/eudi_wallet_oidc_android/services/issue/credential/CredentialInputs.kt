package com.ewc.eudi_wallet_oidc_android.services.issue.credential

import com.ewc.eudi_wallet_oidc_android.models.CredentialRequestEncryptionInfo
import com.ewc.eudi_wallet_oidc_android.models.ECKeyWithAlgEnc

/**
 * The two halves of credential encryption, which only make sense together.
 *
 * The same argument as `WalletAttestation`: these were two parameters a caller could mismatch --
 * an `ecKeyWithAlgEnc` with no `credentialRequestEncryptionInfo` silently asks for an encrypted
 * response over a plaintext request, and the reverse encrypts the request while asking for the
 * answer in the clear.
 *
 * @param responseKey the key the issuer should encrypt the response to, with the `alg` and `enc`
 *   it was generated for. Null asks for a plaintext response.
 * @param request the issuer's own `credential_request_encryption` metadata. Section 10: the client
 *   "MAY encrypt the request when `encryption_required` is `false` and MUST do so when
 *   `encryption_required` is `true`".
 */
data class CredentialEncryption(
    val responseKey: ECKeyWithAlgEnc? = null,
    val request: CredentialRequestEncryptionInfo? = null,
) {
    /** Section 10: the issuer will not accept a plaintext request. */
    val requestEncryptionRequired: Boolean get() = request?.encryptionRequired == true
}
