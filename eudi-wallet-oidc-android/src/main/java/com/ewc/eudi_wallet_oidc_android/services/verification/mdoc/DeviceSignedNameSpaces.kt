package com.ewc.eudi_wallet_oidc_android.services.verification.mdoc

import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import java.io.ByteArrayOutputStream

fun createTaggedEmptyNamespaces(): DataItem {
    val emptyMap = Map() // {}
    val encodedEmptyMap = encodeToCborBytes(emptyMap) // CBOR bytes for {}

    val byteString = ByteString(encodedEmptyMap)
    byteString.setTag(24) // ✅ apply CBOR tag 24 (embedded CBOR)

    return byteString
}

fun encodeToCborBytes(dataItem: co.nstant.`in`.cbor.model.DataItem): ByteArray {
    val baos = ByteArrayOutputStream()
    CborEncoder(baos).encode(dataItem)
    return baos.toByteArray()
}
