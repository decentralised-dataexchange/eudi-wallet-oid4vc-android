package com.ewc.eudi_wallet_oidc_android.services.credentialValidation.helperFunctions


import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.model.ByteString as CborByteString
import co.nstant.`in`.cbor.model.Array as CborArray
import java.security.PublicKey
import co.nstant.`in`.cbor.CborEncoder
import java.io.ByteArrayOutputStream
import java.math.BigInteger

fun verifyCoseSignature(issuerAuth: CborArray, publicKey: PublicKey) {
    // 1. Get raw bytes using CborByteString cast
    val protectedHeader = (issuerAuth.dataItems[0] as CborByteString).bytes
    val payload = (issuerAuth.dataItems[2] as CborByteString).bytes
    var signature = (issuerAuth.dataItems[3] as CborByteString).bytes

    // 2. Build the canonical Sig_structure (Signature1)
    // IMPORTANT: External AAD must be an empty ByteString
    val sigStructure = CborBuilder()
        .addArray()
        .add("Signature1")
        .add(protectedHeader)
        .add(co.nstant.`in`.cbor.model.ByteString(ByteArray(0))) // Explicit ByteString
        .add(payload)
        .end().build()

    val baos = ByteArrayOutputStream()
    CborEncoder(baos).encode(sigStructure)
    val toBeVerified = baos.toByteArray()

    // 3. Fix: Convert raw 64-byte signature to DER if necessary
    // Android/Java's SHA256withECDSA requires DER format
    if (signature.size == 64) {
        signature = rawSignatureToDer(signature)
    }

    // 4. Verify
    val sig = java.security.Signature.getInstance("SHA256withECDSA")
    sig.initVerify(publicKey)
    sig.update(toBeVerified)

    if (!sig.verify(signature)) {
        throw IllegalArgumentException("mso_mdoc signature mismatch: Validation failed.")
    }
}

private fun rawSignatureToDer(raw: ByteArray): ByteArray {
    val r = BigInteger(1, raw.sliceArray(0..31))
    val s = BigInteger(1, raw.sliceArray(32..63))

    val rBytes = r.toByteArray()
    val sBytes = s.toByteArray()

    val out = ByteArrayOutputStream()
    out.write(0x30) // DER Sequence
    out.write(rBytes.size + sBytes.size + 4)
    out.write(0x02) // Integer
    out.write(rBytes.size)
    out.write(rBytes)
    out.write(0x02) // Integer
    out.write(sBytes.size)
    out.write(sBytes)
    return out.toByteArray()
}

