package com.ewc.eudi_wallet_oidc_android.services.dcapi

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.UnicodeString
import com.ewc.eudi_wallet_oidc_android.models.Document
import com.ewc.eudi_wallet_oidc_android.models.IssuerSigned
import com.ewc.eudi_wallet_oidc_android.models.VpToken
import com.ewc.eudi_wallet_oidc_android.services.utils.CborUtils
import com.ewc.eudi_wallet_oidc_android.services.verification.deviceSigned.buildDeviceAuthenticationBytes
import com.ewc.eudi_wallet_oidc_android.services.verification.deviceSigned.buildDeviceSignatureCoseSign1
import com.ewc.eudi_wallet_oidc_android.services.verification.deviceSigned.buildProtectedHeader
import com.ewc.eudi_wallet_oidc_android.services.verification.deviceSigned.encodeEmptyDeviceNameSpaces
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.MajorType
import co.nstant.`in`.cbor.model.SimpleValue

/**
 * Service for ISO 18013-7 Annex C non-OpenID DC API flow.
 *
 * Usage from a CredentialProvider Extension:
 * ```
 * val service = DCAPIService()
 * val result = service.processRequest(
 *     requestJSON = requestFromBrowser,
 *     origin = "https://verifier.example.com",
 *     credentials = listOf(storedMdocCredentialBase64url),
 *     privateKey = devicePrivateKey  // EC P-256 private key for device signing
 * )
 * when (result) {
 *     is Result.Success -> returnToBrowser(result.value)
 *     is Result.Failure -> handleError(result.exception)
 * }
 * ```
 */
class DCAPIService {

    /**
     * Main entry point for ISO 18013-7 Annex C non-OpenID DC API flow.
     *
     * @param requestJSON The DC API request JSON string from the browser.
     * @param origin The calling website origin (e.g., "https://example.com")
     * @param credentials List of base64url-encoded mDOC CBOR credentials
     * @param privateKey EC P-256 private key for device authentication signing
     * @return Result with response JSON string or DCAPIError
     */
    fun processRequest(
        requestJSON: String,
        origin: String,
        credentials: List<String>,
        privateKey: PrivateKey?
    ): Result<String> {
        return try {
            // 1. Parse the request JSON
            val (deviceRequestB64, encryptionInfoB64) = parseRequestJSON(requestJSON)

            // 2. Parse the DeviceRequest CBOR
            val deviceRequest = DeviceRequestParser.parse(deviceRequestB64)

            // 3. Parse the EncryptionInfo CBOR
            val encryptionInfo = EncryptionInfoParser.parse(encryptionInfoB64)

            // 4. Build the DC API session transcript
            val (sessionTranscriptCBOR, sessionTranscriptBytes) = buildSessionTranscriptForDCAPI(
                encryptionInfoBase64 = encryptionInfoB64,
                origin = origin
            )

            // 5. Build documents for each DocRequest
            val documents = mutableListOf<Document>()
            for (docRequest in deviceRequest.docRequests) {
                val document = buildDocument(
                    docRequest = docRequest,
                    credentials = credentials,
                    sessionTranscript = sessionTranscriptCBOR,
                    privateKey = privateKey
                ) ?: continue
                documents.add(document)
            }

            if (documents.isEmpty()) {
                val requestedTypes = deviceRequest.docRequests.joinToString(", ") { it.docType }
                return Result.failure(DCAPIError.NoMatchingCredential(requestedTypes))
            }

            // 6. Build DeviceResponse and CBOR-encode
            val vpToken = VpToken(
                version = "1.0",
                documents = documents,
                status = 0
            )
            val deviceResponseBytes = CborUtils.encodeMDocToCbor(vpToken)

            // 7. HPKE encrypt
            val encryptionResult = HPKEEncryptor.encrypt(
                plaintext = deviceResponseBytes,
                recipientPublicKey = encryptionInfo.recipientPublicKey,
                info = sessionTranscriptBytes
            )

            // 8. Build response JSON
            val responseString = DCAPIResponseBuilder.buildResponseJSONString(encryptionResult)

            Result.success(responseString)
        } catch (e: DCAPIError) {
            Result.failure(e)
        } catch (e: Exception) {
            Result.failure(DCAPIError.InvalidRequestJSON(e.message ?: "Unknown error"))
        }
    }

    private fun parseRequestJSON(json: String): Pair<String, String> {
        val parsed = JSONObject(json)

        val firstRequest: JSONObject = when {
            parsed.has("requests") -> {
                val requests = parsed.getJSONArray("requests")
                if (requests.length() == 0) throw DCAPIError.InvalidRequestJSON("Empty 'requests' array")
                requests.getJSONObject(0)
            }
            parsed.has("protocol") -> parsed
            else -> throw DCAPIError.InvalidRequestJSON("Missing 'requests' array or 'protocol' field")
        }

        val protocol = firstRequest.optString("protocol", "")
        if (protocol != "org-iso-mdoc") {
            throw DCAPIError.UnsupportedProtocol(protocol)
        }

        val data = firstRequest.optJSONObject("data")
            ?: throw DCAPIError.InvalidRequestJSON("Missing 'data' object")
        val deviceRequestB64 = data.optString("deviceRequest", "")
        val encryptionInfoB64 = data.optString("encryptionInfo", "")
        if (deviceRequestB64.isEmpty() || encryptionInfoB64.isEmpty()) {
            throw DCAPIError.InvalidRequestJSON("Missing 'deviceRequest' or 'encryptionInfo'")
        }

        return Pair(deviceRequestB64, encryptionInfoB64)
    }

    @OptIn(kotlin.io.encoding.ExperimentalEncodingApi::class)
    private fun buildDocument(
        docRequest: ParsedDocRequest,
        credentials: List<String>,
        sessionTranscript: CborArray,
        privateKey: PrivateKey?
    ): Document? {
        // Find a matching credential by docType
        var matchedCredential: String? = null
        for (credential in credentials) {
            if (credential.contains(".")) continue
            try {
                val paddedCbor = padBase64Url(credential)
                val cborBytes = kotlin.io.encoding.Base64.UrlSafe.decode(paddedCbor)
                val cbors = CborDecoder(ByteArrayInputStream(cborBytes)).decode()
                val issuerAuth = cbors[0]["issuerAuth"] ?: continue
                val credDocType = getDocType(issuerAuth)
                if (credDocType == docRequest.docType) {
                    matchedCredential = credential
                    break
                }
            } catch (_: Exception) {
                continue
            }
        }

        matchedCredential ?: return null

        val paddedCbor = padBase64Url(matchedCredential)
        val cborBytes = kotlin.io.encoding.Base64.UrlSafe.decode(paddedCbor)
        val cbors = CborDecoder(ByteArrayInputStream(cborBytes)).decode()

        val issuerAuth = cbors[0]["issuerAuth"] as? CborArray ?: return null
        val nameSpaces = cbors[0]["nameSpaces"] as? CborMap ?: return null

        // Filter nameSpaces by the DeviceRequest's requested elements
        val filteredNameSpaces = filterNameSpacesByDeviceRequest(nameSpaces, docRequest.requestedNamespaces)

        // Build DeviceSigned
        val deviceSigned = buildDeviceSignedForDCAPI(
            privateKey = privateKey,
            sessionTranscript = sessionTranscript,
            docType = docRequest.docType
        )

        return Document(
            docType = docRequest.docType,
            issuerSigned = IssuerSigned(
                nameSpaces = filteredNameSpaces ?: nameSpaces,
                issuerAuth = issuerAuth
            ),
            deviceSigned = deviceSigned
        )
    }

    private fun buildDeviceSignedForDCAPI(
        privateKey: PrivateKey?,
        sessionTranscript: CborArray,
        docType: String
    ): com.ewc.eudi_wallet_oidc_android.models.DeviceSigned {
        val emptyNamespaces = encodeEmptyDeviceNameSpaces()
        val deviceAuthMap = CborMap()

        if (privateKey != null) {
            val protectedHeaderBytes = buildProtectedHeader()
            val deviceAuthBytes = buildDeviceAuthenticationBytes(
                sessionTranscriptArray = sessionTranscript,
                docType = docType,
                deviceNameSpacesBytes = emptyNamespaces
            )

            val coseSign1 = buildDeviceSignatureCoseSign1(
                deviceAuthenticationBytes = deviceAuthBytes,
                protectedHeaderBytes = protectedHeaderBytes,
                privateKey = privateKey
            )

            deviceAuthMap.put(UnicodeString("deviceSignature"), coseSign1)
        }

        return com.ewc.eudi_wallet_oidc_android.models.DeviceSigned(
            nameSpaces = emptyNamespaces,
            deviceAuth = deviceAuthMap
        )
    }

    private fun filterNameSpacesByDeviceRequest(
        nameSpaces: CborMap,
        requestedNamespaces: Map<String, Map<String, Boolean>>
    ): CborMap? {
        val filtered = CborMap()
        var hasEntries = false

        for (key in nameSpaces.keys) {
            val namespaceName = (key as? UnicodeString)?.string ?: continue
            val requestedElements = requestedNamespaces[namespaceName] ?: continue
            val namespaceArray = nameSpaces[key] as? CborArray ?: continue

            if (requestedElements.isEmpty()) {
                filtered.put(key, namespaceArray)
                hasEntries = true
                continue
            }

            val filteredArray = CborArray()
            var hasItems = false
            for (item in namespaceArray.dataItems) {
                if (item is ByteString || (item.tag != null && item.tag.value == 24L)) {
                    val bytes = when (item) {
                        is ByteString -> item.bytes
                        else -> (item as? ByteString)?.bytes ?: continue
                    }
                    try {
                        val decoded = CborDecoder(ByteArrayInputStream(bytes)).decode()
                        val decodedMap = decoded.firstOrNull() as? CborMap ?: continue
                        val identifier = (decodedMap[UnicodeString("elementIdentifier")] as? UnicodeString)?.string
                        if (identifier != null && requestedElements.containsKey(identifier)) {
                            filteredArray.add(item)
                            hasItems = true
                        }
                    } catch (_: Exception) {
                        continue
                    }
                }
            }

            if (hasItems) {
                filtered.put(key, filteredArray)
                hasEntries = true
            }
        }

        return if (hasEntries) filtered else null
    }

    private fun getDocType(issuerAuth: DataItem): String? {
        if (issuerAuth !is CborArray) return null
        for (element in issuerAuth.dataItems) {
            if (element !is ByteString) continue
            try {
                val nested = CborDecoder(ByteArrayInputStream(element.bytes)).decode()
                val nestedItem = nested.firstOrNull() ?: continue
                if (nestedItem.tag?.value == 24L && nestedItem is ByteString) {
                    val innerDecoded = CborDecoder(ByteArrayInputStream(nestedItem.bytes)).decode()
                    val innerMap = innerDecoded.firstOrNull() as? CborMap ?: continue
                    val docType = (innerMap[UnicodeString("docType")] as? UnicodeString)?.string
                    if (!docType.isNullOrEmpty()) return docType
                }
                if (nestedItem is CborMap) {
                    val docType = (nestedItem[UnicodeString("docType")] as? UnicodeString)?.string
                    if (!docType.isNullOrEmpty()) return docType
                }
            } catch (_: Exception) {
                continue
            }
        }
        return null
    }

    private fun encodeCborItem(dataItem: DataItem): ByteArray {
        val baos = ByteArrayOutputStream()
        CborEncoder(baos).encode(dataItem)
        return baos.toByteArray()
    }

    private fun padBase64Url(input: String): String {
        val mod = input.length % 4
        return if (mod == 0) input else input + "=".repeat(4 - mod)
    }

    // Helper extension for CBOR map access
    private operator fun DataItem.get(key: String): DataItem? {
        return (this as? CborMap)?.get(UnicodeString(key))
    }
}
