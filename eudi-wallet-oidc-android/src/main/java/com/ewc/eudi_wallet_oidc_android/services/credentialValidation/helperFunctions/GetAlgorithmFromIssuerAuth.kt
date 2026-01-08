package com.ewc.eudi_wallet_oidc_android.services.credentialValidation.helperFunctions

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.UnsignedInteger
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString as CborByteString
import co.nstant.`in`.cbor.model.Map as CborMap

fun getCoseAlgorithm(issuerAuth: CborArray): CoseAlgorithm {
    // 1. Get Protected Header (Index 0)
    val protectedHeaderBytes =
        (issuerAuth.dataItems[0] as? CborByteString)?.bytes
            ?: throw IllegalArgumentException("Protected header missing or not a ByteString")

    // 2. Decode the Map
    val decodedList = CborDecoder.decode(protectedHeaderBytes)
    val protectedMap = decodedList.firstOrNull() as? CborMap
        ?: throw IllegalArgumentException("Protected header is not a CBOR map")

    // 3. Get Label 1 (alg)
    val algValue = protectedMap.get(UnsignedInteger(1))
        ?: throw IllegalArgumentException("Algorithm label (1) not found in protected header")

    // 4. Extract algorithm ID
    val algId = when (algValue) {
        is NegativeInteger -> algValue.value.toLong()
        is UnsignedInteger -> algValue.value.toLong()
        else -> throw IllegalArgumentException("Invalid COSE alg value type")
    }

    // 5. Return typed COSE algorithm
    return CoseAlgorithm.fromId(algId)
}


enum class CoseAlgorithm(val id: Long, val fullName: String) {

    // ---- ECDSA ------------------------------------------------------------
    ES256(-7, "ES256"),
    ES384(-35, "ES384"),
    ES512(-36, "ES512"),

    // ---- Edwards ----------------------------------------------------------
    EDDSA(-8, "EdDSA");

    companion object {
        fun fromId(id: Long): CoseAlgorithm =
            values().firstOrNull { it.id == id }
                ?: throw IllegalArgumentException(
                    "Unsupported or unknown COSE algorithm ID: $id"
                )
    }
}
