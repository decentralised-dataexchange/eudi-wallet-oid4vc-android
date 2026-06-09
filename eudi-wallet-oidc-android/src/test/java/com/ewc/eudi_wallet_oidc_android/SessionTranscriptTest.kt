package com.ewc.eudi_wallet_oidc_android

import com.ewc.eudi_wallet_oidc_android.services.verification.deviceSigned.buildSessionTranscriptForAnnexB18013_7
import org.junit.Assert.assertEquals
import org.junit.Test

class SessionTranscriptTest {

    // Fixed inputs shared with the iOS + Python oracle cross-check.
    private val clientId = "x509_san_dns:verifier.example.com"
    private val nonce = "abc123nonce"
    private val responseUri = "https://verifier.example.com/response"

    // Expected hex from cbor2 (Python) reference oracle for ISO/IEC TS 18013-7 §B.4.4.
    private val expectedAnnexB =
        "83f6f68358209931fddd7d5a6be54343f3cbf96ade069322940201e993a003b4e187aa4e929a582000bc1a24fd8af2240ff62f365a22a2706a3cab9647e78a23f433458c7b73e77a6b6162633132336e6f6e6365"

    @Test
    fun annexB18013_7TranscriptMatchesOracle() {
        val (_, bytes) = buildSessionTranscriptForAnnexB18013_7(
            clientId = clientId,
            nonce = nonce,
            responseUri = responseUri
        )
        val hex = bytes.joinToString("") { "%02x".format(it) }
        println("ANDROID ANNEXB $hex")
        assertEquals(expectedAnnexB, hex)
    }
}
