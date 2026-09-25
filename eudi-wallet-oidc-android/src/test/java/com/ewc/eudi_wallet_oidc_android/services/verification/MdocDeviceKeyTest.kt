package com.ewc.eudi_wallet_oidc_android.services.verification

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import com.ewc.eudi_wallet_oidc_android.services.utils.CborUtils
import com.ewc.eudi_wallet_oidc_android.services.verification.deviceSigned.buildDeviceSignatureCoseSign1
import com.ewc.eudi_wallet_oidc_android.services.verification.deviceSigned.buildProtectedHeader
import com.nimbusds.jose.crypto.impl.ECDSA
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.PrivateKey
import java.security.Signature
import java.util.Base64

class MdocDeviceKeyTest {

    private fun encode(item: DataItem): ByteArray =
        ByteArrayOutputStream().also { CborEncoder(it).encode(item) }.toByteArray()

    /** A minimal IssuerSigned whose MSO binds [deviceKey], base64url. */
    private fun issuerSigned(deviceKey: ECKey?): String {
        val mso = CborMap().apply {
            put(UnicodeString("docType"), UnicodeString("org.iso.18013.5.1.mDL"))
            if (deviceKey != null) {
                val coseKey = CborMap().apply {
                    put(UnsignedInteger(1), UnsignedInteger(2))
                    put(NegativeInteger(-1), UnsignedInteger(1))
                    put(NegativeInteger(-2), ByteString(deviceKey.x.decode()))
                    put(NegativeInteger(-3), ByteString(deviceKey.y.decode()))
                }
                put(UnicodeString("deviceKeyInfo"), CborMap().apply { put(UnicodeString("deviceKey"), coseKey) })
            }
        }
        val taggedMso = ByteString(encode(mso)).apply { setTag(24) }
        val issuerAuth = CborArray().apply {
            add(ByteString(buildProtectedHeader()))
            add(CborMap())
            add(ByteString(encode(taggedMso)))
            add(ByteString(ByteArray(64)))
        }
        val signed = CborMap().apply {
            put(UnicodeString("nameSpaces"), CborMap())
            put(UnicodeString("issuerAuth"), issuerAuth)
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(encode(signed))
    }

    @Test
    fun `device key is read from the MSO`() {
        val key = ECKeyGenerator(Curve.P_256).generate()
        val read = CborUtils.extractDeviceKeyFromIssuerSigned(issuerSigned(key))
        assertEquals(key.computeThumbprint(), read?.computeThumbprint())
    }

    @Test
    fun `no device key in the MSO reads as null`() {
        assertNull(CborUtils.extractDeviceKeyFromIssuerSigned(issuerSigned(null)))
        assertNull(CborUtils.extractDeviceKeyFromIssuerSigned("not-cbor"))
    }

    @Test
    fun `software key signs the device authentication as before`() {
        val key = ECKeyGenerator(Curve.P_256).generate()
        // The builders now take the key as a PrivateKey.
        val privateKey: PrivateKey = key.toPrivateKey()
        val protectedHeader = buildProtectedHeader()
        val payload = byteArrayOf(0xd8.toByte(), 0x18, 0x41, 0x00)

        val coseSign1 = buildDeviceSignatureCoseSign1(payload, protectedHeader, privateKey)

        val items = coseSign1.dataItems
        assertEquals(4, items.size)
        assertTrue((items[0] as ByteString).bytes.contentEquals(protectedHeader))
        assertTrue((items[1] as CborMap).keys.isEmpty())
        assertEquals(SimpleValue.NULL, items[2])
        val signature = (items[3] as ByteString).bytes
        assertEquals(64, signature.size)

        val sigStructure = CborArray().apply {
            add(UnicodeString("Signature1"))
            add(ByteString(protectedHeader))
            add(ByteString(ByteArray(0)))
            add(ByteString(payload))
        }
        val verifier = Signature.getInstance("SHA256withECDSA").apply {
            initVerify(key.toPublicKey())
            update(encode(sigStructure))
        }
        assertTrue(verifier.verify(ECDSA.transcodeSignatureToDER(signature)))
        // Round-trips as CBOR.
        assertEquals(coseSign1, CborDecoder(ByteArrayInputStream(encode(coseSign1))).decode().first())
    }
}
