package com.ewc.eudi_wallet_oidc_android.services.credentialRevocation

import java.util.Base64
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class VerifiableCredentialsStatusList2021Model(private val encodedStr: String? = null, sizeKB: Int = 16) {
    private val bitLength: Int = sizeKB * 1024 * 8 // Convert KB to bits (16KB = 131,072 bits)
    private var bitstring: MutableList<Char>

    init {
        bitstring = if (encodedStr != null) {
            val decompressedData = decodeAndDecompress(encodedStr)
            convertToBitstring(decompressedData).toMutableList()
        } else {
            MutableList(bitLength) { '0' } // Initialize all bits as '0'
        }
    }

    // Decode Base64 and decompress GZIP
    private fun decodeAndDecompress(encoded: String): ByteArray {
        return try {
            val paddedStr = encoded.padEnd((encoded.length + 3) / 4 * 4, '=') // Add padding
            val decodedBytes = try {
                Base64.getUrlDecoder().decode(paddedStr)
            } catch (e: Exception) {
                Base64.getDecoder().decode(paddedStr)
            }
            GZIPInputStream(ByteArrayInputStream(decodedBytes)).use { it.readBytes() }
        } catch (e: Exception) {
            throw IllegalArgumentException("Error during decoding/decompression: ${e.message}")
        }
    }

    // Convert bytes to a full bitstring
    private fun convertToBitstring(data: ByteArray): String {
        return data.joinToString("") { byte -> String.format("%8s", byte.toInt().and(0xFF).toString(2)).replace(' ', '0') }
    }

    // Set a specific bit to '0' or '1'
    fun setBit(index: Int, value: Int) {
        if (index !in 0 until bitLength) throw IndexOutOfBoundsException("Index $index out of range (0 to ${bitLength - 1})")
        if (value !in 0..1) throw IllegalArgumentException("Value must be 0 or 1.")
        bitstring[index] = if (value == 1) '1' else '0'
    }

    // Retrieve a specific bit
    fun getBit(index: Int): Char {
        if (index !in bitstring.indices) throw IndexOutOfBoundsException("Bit index out of range.")
        return bitstring[index]
    }

    // Convert bitstring into a byte array (8 bits per byte)
    private fun convertToBytes(): ByteArray {
        val bitstringStr = bitstring.joinToString("")
        val byteArraySize = bitstringStr.length / 8
        return bitstringStr.chunked(8).map { it.toInt(2).toByte() }.toByteArray()
    }

    // Compress and Base64 encode the bitstring
    fun generateEncodedString(): String {
        val byteData = convertToBytes()
        val compressedData = ByteArrayOutputStream().use { baos ->
            GZIPOutputStream(baos).use { it.write(byteData) }
            baos.toByteArray()
        }
        return Base64.getEncoder().encodeToString(compressedData)
    }
}
