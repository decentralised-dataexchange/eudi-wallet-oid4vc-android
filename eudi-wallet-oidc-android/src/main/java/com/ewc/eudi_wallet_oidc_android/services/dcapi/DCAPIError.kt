package com.ewc.eudi_wallet_oidc_android.services.dcapi

sealed class DCAPIError(override val message: String) : Exception(message) {
    class InvalidRequestJSON(detail: String) : DCAPIError("Invalid DC API request JSON: $detail")
    class UnsupportedProtocol(protocol: String) : DCAPIError("Unsupported protocol: $protocol")
    class InvalidDeviceRequest(detail: String) : DCAPIError("Invalid DeviceRequest CBOR: $detail")
    class InvalidEncryptionInfo(detail: String) : DCAPIError("Invalid EncryptionInfo CBOR: $detail")
    class UnsupportedCipherSuite(id: Int) : DCAPIError("Unsupported cipher suite: $id")
    class NoMatchingCredential(docType: String) : DCAPIError("No matching credential for docType: $docType")
    class DeviceSigningFailed : DCAPIError("Device signing failed")
    class HPKEEncryptionFailed(detail: String) : DCAPIError("HPKE encryption failed: $detail")
    class CborEncodingFailed : DCAPIError("CBOR encoding failed")
}
