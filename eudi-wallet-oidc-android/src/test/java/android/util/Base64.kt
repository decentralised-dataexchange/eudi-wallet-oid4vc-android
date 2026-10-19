package android.util

import java.util.Base64 as JavaBase64

/**
 * JVM unit tests only: stands in for the android.jar stub, which `returnDefaultValues` turns into
 * a method that returns null, so every code path that encodes or decodes with it silently
 * produces nothing. Mirrors the Android contract: [URL_SAFE] picks the alphabet, [NO_PADDING] and
 * [NO_WRAP] shape the output, and decoding accepts input with or without padding. Test classes
 * come first on the unit-test classpath.
 */
@Suppress("unused")
object Base64 {
    const val DEFAULT = 0
    const val NO_PADDING = 1
    const val NO_WRAP = 2
    const val CRLF = 4
    const val URL_SAFE = 8
    const val NO_CLOSE = 16

    @JvmStatic
    fun decode(str: String, flags: Int): ByteArray = decode(str.toByteArray(Charsets.US_ASCII), flags)

    @JvmStatic
    fun decode(input: ByteArray, flags: Int): ByteArray {
        val cleaned = String(input, Charsets.US_ASCII).filterNot { it.isWhitespace() }.trimEnd('=')
        val decoder = if (flags and URL_SAFE != 0) JavaBase64.getUrlDecoder() else JavaBase64.getDecoder()
        return decoder.decode(cleaned)
    }

    @JvmStatic
    fun encodeToString(input: ByteArray, flags: Int): String =
        String(encode(input, flags), Charsets.US_ASCII)

    @JvmStatic
    fun encode(input: ByteArray, flags: Int): ByteArray {
        var encoder = if (flags and URL_SAFE != 0) JavaBase64.getUrlEncoder() else JavaBase64.getEncoder()
        if (flags and NO_PADDING != 0) encoder = encoder.withoutPadding()
        val encoded = encoder.encodeToString(input)
        if (flags and NO_WRAP != 0) return encoded.toByteArray(Charsets.US_ASCII)
        val separator = if (flags and CRLF != 0) "\r\n" else "\n"
        return (encoded.chunked(76).joinToString(separator) + separator).toByteArray(Charsets.US_ASCII)
    }
}
