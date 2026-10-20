package com.ewc.eudi_wallet_oidc_android.services.verification.presentation

/** Why a presentation could not be built. The description is meant for a user. */
sealed class PresentationException(message: String, cause: Throwable? = null) : Exception(message, cause) {

    /** No key to prove possession with: neither the credential's nor the holder's. */
    class NoKey(entryId: String) : PresentationException("No key is available to present the credential for $entryId")

    /** The key binding JWT of an SD-JWT could not be signed. */
    class KeyBindingFailed(entryId: String, cause: Throwable?) :
        PresentationException("The key binding for $entryId could not be signed", cause)

    /** The mdoc device signature could not be made. */
    class DeviceSignatureFailed(entryId: String, cause: Throwable?) :
        PresentationException("The device signature for $entryId could not be made", cause)

    /** The W3C presentation could not be signed. */
    class PresentationSigningFailed(entryId: String, cause: Throwable?) :
        PresentationException("The presentation for $entryId could not be signed", cause)

    /** The credential is in no format this SDK can present. */
    class UnsupportedFormat(entryId: String) :
        PresentationException("The credential for $entryId is in a format that cannot be presented")
}
