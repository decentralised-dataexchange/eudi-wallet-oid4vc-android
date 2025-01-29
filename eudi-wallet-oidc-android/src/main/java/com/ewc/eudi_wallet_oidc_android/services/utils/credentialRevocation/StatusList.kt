//package io.igrant.mobileagent.utils.credentialRevocation
package com.ewc.eudi_wallet_oidc_android.services.utils.credentialRevocation
import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.zip.Deflater
import java.util.zip.Inflater
import java.util.zip.InflaterInputStream

class StatusList(private var size: Int, private var bits: Int) {
    private var list: ByteArray
    private val divisor: Int

    init {
        divisor = 8 / bits
        list = ByteArray(size / divisor)
    }

    companion object {
        fun fromEncoded(encoded: String, bits: Int = 1): StatusList {
            val newInstance = StatusList(0, bits)
            newInstance.decode(encoded)
            return newInstance
        }
    }

    fun encodeAsString(): String {
        val compressed = compress(list)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(compressed)
    }

    fun encodeAsBytes(): ByteArray {
        return compress(list)
    }

    fun encodeAsJSON(): Map<String, Any> {
        val encodedList = encodeAsString()
        return mapOf("bits" to bits, "lst" to encodedList)
    }

    fun encodeAsCBOR(): Map<String, Any> {
        val encodedList = encodeAsBytes()
        return mapOf("bits" to bits, "lst" to encodedList)
    }

    fun encodeAsCBORRaw(): ByteArray {
        val cbor = encodeAsCBOR()
        return cborToBytes(cbor) // Replace with a CBOR library serialization method.
    }

    fun decode(input: String) {
        val paddedInput = input + "=".repeat((4 - input.length % 4) % 4)
        val decoded = Base64.getUrlDecoder().decode(paddedInput)
        list = decompress(decoded)
        size = list.size * divisor
    }

    fun set(pos: Int, value: Int) {
        require(value < (1 shl bits))
        val rest = pos % divisor
        val floored = pos / divisor
        val shift = rest * bits
        val mask = 0xFF.inv() or (((1 shl bits) - 1) shl shift).inv()
        list[floored] = (list[floored].toInt() and mask or (value shl shift)).toByte()
    }

    fun get(pos: Int): Int {
        val rest = pos % divisor
        val floored = pos / divisor
        val shift = rest * bits
        return (list[floored].toInt() and (((1 shl bits) - 1) shl shift)) shr shift
    }

    override fun toString(): String {
        val sb = StringBuilder()
        for (x in 0 until size) {
            sb.append(get(x).toString(16))
        }
        return sb.toString()
    }

    private fun compress(data: ByteArray): ByteArray {
        val deflater = Deflater(Deflater.BEST_COMPRESSION)
        deflater.setInput(data)
        deflater.finish()
        val output = ByteArray(data.size * 2)
        val compressedSize = deflater.deflate(output)
        deflater.end()
        return output.copyOf(compressedSize)
    }

    private fun decompress(data: ByteArray): ByteArray {
        val inflater = Inflater()
        val outputStream = ByteArrayOutputStream()
        InflaterInputStream(data.inputStream(), inflater).use { input ->
            val buffer = ByteArray(1024) // Read in chunks
            var bytesRead: Int
            while (input.read(buffer).also { bytesRead = it } != -1) {
                outputStream.write(buffer, 0, bytesRead)
            }
        }
        return outputStream.toByteArray()
    }

    private fun cborToBytes(cbor: Map<String, Any>): ByteArray {
        // Implement CBOR serialization using a library like Jackson or CBOR-java
        throw NotImplementedError("CBOR serialization not implemented")
    }
}