package com.ewc.eudi_wallet_oidc_android.models

import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.Map as CborMap

data class VpToken(
    val version: String,
    val documents: List<Document>,
    val status: Int
)

data class Document(
    val docType: String,
    val issuerSigned: IssuerSigned,
    val deviceSigned: DeviceSigned?
)

data class IssuerSigned(
    val nameSpaces: CborMap,
    val issuerAuth: CborArray
)

data class DeviceSigned(
    val nameSpaces: ByteString,
    val deviceAuth: DeviceAuth
)

data class DeviceAuth(
    val deviceSignature: List<Any>
)