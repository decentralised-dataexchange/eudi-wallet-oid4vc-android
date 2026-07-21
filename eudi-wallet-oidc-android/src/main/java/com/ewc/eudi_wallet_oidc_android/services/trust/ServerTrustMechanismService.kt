package com.ewc.eudi_wallet_oidc_android.services.trust

import android.util.Base64
import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.DigitalId
import com.ewc.eudi_wallet_oidc_android.models.ElectronicAddress
import com.ewc.eudi_wallet_oidc_android.models.LangValue
import com.ewc.eudi_wallet_oidc_android.models.PostalAddress
import com.ewc.eudi_wallet_oidc_android.models.PostalAddresses
import com.ewc.eudi_wallet_oidc_android.models.SchemeOperatorAddress
import com.ewc.eudi_wallet_oidc_android.models.SchemeOperatorName
import com.ewc.eudi_wallet_oidc_android.models.ServiceDigitalIdentity
import com.ewc.eudi_wallet_oidc_android.models.ServiceInformation
import com.ewc.eudi_wallet_oidc_android.models.TSPInformation
import com.ewc.eudi_wallet_oidc_android.models.TSPService
import com.ewc.eudi_wallet_oidc_android.models.TSPServices
import com.ewc.eudi_wallet_oidc_android.models.TrustListEntry
import com.ewc.eudi_wallet_oidc_android.models.TrustListLookupRequest
import com.ewc.eudi_wallet_oidc_android.models.TrustListLookupResponse
import com.ewc.eudi_wallet_oidc_android.models.TrustServiceProvider
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager

/**
 * Server-backed implementation of [TrustMechanismInterface] that evaluates trust against the OWS
 * Trust List backend, instead of the local/static trust list used by [TrustMechanismService].
 *
 * The lookup endpoint is open — a single POST /trust-list/lookup with the verifier/issuer
 * identifier (x5c / kid / did / jwksUri). No device auth or Play Integrity is involved.
 *
 * SDK internals with no Context (e.g. TrustEvaluator) can use `ServerTrustMechanismService()`.
 * Fail-closed: any failure resolves to "not trusted".
 */
class ServerTrustMechanismService(
    private val baseUrl: String? = null
) : TrustMechanismInterface {

    companion object {
        private const val TAG = "ServerTrustMechanism"

        // TODO(trust-api): TEST environment. Override via init(...) for production.
        const val DEFAULT_BASE_URL = "https://trustlist.nxd.foundation"

        // TrustEvaluator.findTrustedX5c combines a kid with its jwksUri as "kid##SEP##jwksUri".
        private const val KID_JWKS_SEPARATOR = "##SEP##"

        @Volatile private var configuredBaseUrl: String = DEFAULT_BASE_URL

        /** Optionally override the trust-list base URL (e.g. test vs prod). */
        fun init(baseUrl: String) {
            configuredBaseUrl = baseUrl
        }
    }

    private val resolvedBaseUrl: String get() = baseUrl ?: configuredBaseUrl
    private val lookupUrl get() = "$resolvedBaseUrl/trust-list/lookup"

    override suspend fun isIssuerOrVerifierTrusted(
        url: String?,
        x5c: String?,
        trustProvidersList: List<TrustServiceProvider>?,
        isDCQLVerificationFlow: Boolean
    ): Boolean {
        val response = lookup(x5c) ?: return false

        return if (isDCQLVerificationFlow) {
            val responseUrl = response.entry?.trustList?.url
            !url.isNullOrEmpty() && url == responseUrl
        } else {
            response.match == true
        }
    }

    override suspend fun fetchTrustDetails(
        url: String?,
        x5c: String?,
        trustProvidersList: List<TrustServiceProvider>?
    ): TrustServiceProvider? {
        val response = lookup(x5c) ?: return null
        if (!response.match) return null
        return response.entry?.let { mapToTrustServiceProvider(it) }
    }

    /** POST /trust-list/lookup (open endpoint). Fail-closed to null. */
    private suspend fun lookup(x5c: String?): TrustListLookupResponse? {
        if (x5c.isNullOrBlank()) {
            Log.e(TAG, "No identifier supplied; failing closed")
            return null
        }
        val body = buildLookupRequest(x5c)
        Log.d(TAG, "Trust lookup by ${if (body.x5c != null) "x5c" else if (body.did != null) "did" else "kid"}")

        val response = try {
            ApiManager.api.getService()?.trustListLookup(lookupUrl, body)
        } catch (e: Exception) {
            Log.e(TAG, "Trust lookup error: ${e.message}")
            null
        }

        return if (response?.isSuccessful == true) {
            response.body()
        } else {
            Log.e(TAG, "Trust lookup failed: ${response?.code()}")
            null
        }
    }

    /**
     * Builds the lookup body from whatever identifier the caller supplies — an x5c cert, a plain
     * kid, a DID, or a "kid##SEP##jwksUri" combined key — mapping each onto the correct request field.
     */
    private fun buildLookupRequest(identifier: String): TrustListLookupRequest = when {
        identifier.contains(KID_JWKS_SEPARATOR) ->
            TrustListLookupRequest(kid = identifier.substringBefore(KID_JWKS_SEPARATOR))
        identifier.startsWith("did:") ->
            TrustListLookupRequest(did = identifier)
        isX509Certificate(identifier) ->
            TrustListLookupRequest(x5c = listOf(identifier))
        else ->
            TrustListLookupRequest(kid = identifier)
    }

    /** True if [value] is a base64-DER X.509 certificate (i.e. an x5c), false for a kid/DID string. */
    private fun isX509Certificate(value: String): Boolean = try {
        val der = Base64.decode(value, Base64.DEFAULT)
        java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(der.inputStream()) != null
    } catch (e: Exception) {
        false
    }

    /**
     * Maps the flat OWS Trust List [entry] onto the nested TSL [TrustServiceProvider] structure the
     * trust-provider detail UI reads (name, address, email, service info, digital identity).
     */
    private fun mapToTrustServiceProvider(entry: TrustListEntry): TrustServiceProvider {
        val provider = entry.provider
        val postalAddress = PostalAddress(
            streetAddress = provider?.streetAddress,
            locality = provider?.locality,
            postalCode = provider?.postalCode,
            countryName = provider?.countryName
        )
        val tspAddress = SchemeOperatorAddress(
            postalAddresses = PostalAddresses(postalAddress = postalAddress),
            electronicAddress = provider?.electronicAddress?.let {
                ElectronicAddress(uri = LangValue(value = it))
            }
        )
        val tspInformation = TSPInformation(
            tspName = provider?.tSPName,
            tspTradeName = provider?.tSPTradeName?.let { SchemeOperatorName(name = LangValue(value = it)) },
            tspAddress = tspAddress,
            tspInformationURI = provider?.tSPInformationURI
        )

        val service = entry.service
        val cert = service?.digitalIdentity?.firstOrNull()
            ?.replace(Regex("\\s"), "")
            ?.takeIf { it.isNotBlank() }
        val matchedIndex = entry.matchedCertIndex ?: 0
        val subjectKeyIdentifier = entry.certificateDetails?.getOrNull(matchedIndex)?.subjectKeyIdentifier
            ?: entry.certificateDetails?.firstOrNull()?.subjectKeyIdentifier
        val serviceDigitalIdentity = if (cert != null || subjectKeyIdentifier != null) {
            ServiceDigitalIdentity(
                digitalId = DigitalId(x509Certificate = cert, x509SKI = subjectKeyIdentifier)
            )
        } else {
            null
        }
        val serviceInformation = ServiceInformation(
            serviceTypeIdentifier = service?.serviceTypeIdentifier,
            serviceName = service?.serviceName?.let { SchemeOperatorName(name = LangValue(value = it)) },
            serviceStatus = service?.serviceStatus,
            statusStartingTime = service?.statusStartingTime,
            serviceDigitalIdentity = serviceDigitalIdentity
        )
        val tspServices = listOf(
            TSPServices(tspService = TSPService(serviceInformation = serviceInformation))
        )

        return TrustServiceProvider(tspInformation = tspInformation, tspServices = tspServices)
    }
}
