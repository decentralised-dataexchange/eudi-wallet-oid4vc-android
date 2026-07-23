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
import com.ewc.eudi_wallet_oidc_android.models.TrustServiceStatus
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

        /** Path of the lookup endpoint, appended to the base URL. */
        const val DEFAULT_LOOKUP_PATH = "/trust-list/lookup"

        @Volatile private var configuredBaseUrl: String = DEFAULT_BASE_URL
        @Volatile private var configuredLookupPath: String = DEFAULT_LOOKUP_PATH

        /**
         * Optionally override the trust-list endpoint (e.g. test vs prod). [lookupPath] is left
         * unchanged when null, so existing callers keep the default path.
         */
        fun init(baseUrl: String, lookupPath: String? = null) {
            configuredBaseUrl = baseUrl
            if (!lookupPath.isNullOrBlank()) {
                configuredLookupPath = lookupPath
            }
        }
    }

    private val resolvedBaseUrl: String get() = baseUrl ?: configuredBaseUrl

    /** Joins base and path tolerantly — either side may or may not carry the separating slash. */
    private val lookupUrl: String
        get() = resolvedBaseUrl.trimEnd('/') + "/" + configuredLookupPath.trimStart('/')

    override suspend fun isIssuerOrVerifierTrusted(
        url: String?,
        x5c: String?,
        trustProvidersList: List<TrustServiceProvider>?,
        isDCQLVerificationFlow: Boolean
    ): Boolean {
        val response = lookup(x5c) ?: return false

        logDroppedEntries(response)

        return if (isDCQLVerificationFlow) {
            // Only granted services count — an identifier withdrawn in the requested list is not trusted.
            val responseUrls = response.grantedEntries.mapNotNull { it.trustList?.url }
            !url.isNullOrEmpty() && responseUrls.contains(url)
        } else {
            response.match == true && response.grantedEntries.isNotEmpty()
        }
    }
    override suspend fun fetchTrustDetails(
        url: String?,
        x5c: String?,
        trustProvidersList: List<TrustServiceProvider>?
    ): TrustServiceProvider? {
        val response = lookup(x5c) ?: return null
        if (!response.match) return null
        logDroppedEntries(response)
        val entries = response.grantedEntries
        if (entries.isEmpty()) {
            Log.e(TAG, "match=true but no granted entries in response; failing closed")
            return null
        }
        return mapToTrustServiceProvider(entries)
    }

    /**
     * Logs entries refused because their service status is not granted, so a "not trusted" result is
     * traceable to a withdrawn (or unparseable) status rather than looking like a failed lookup.
     */
    private fun logDroppedEntries(response: TrustListLookupResponse) {
        response.matchedEntries
            .filter { !it.serviceStatusValue.isTrusted }
            .forEach { entry ->
                Log.e(
                    TAG,
                    "Dropped entry '${entry.service?.serviceTypeIdentifier}' from " +
                            "'${entry.trustList?.url}' — status=${entry.serviceStatusValue} " +
                            "(raw=${entry.service?.serviceStatus ?: entry.status})"
                )
            }
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
     * Maps the matched OWS Trust List [entries] onto the nested TSL [TrustServiceProvider] the
     * detail UI reads. Provider identity/address come from the first entry; every entry contributes
     * one service, so callers see all service types (and roles) the identifier matched.
     */
    private fun mapToTrustServiceProvider(entries: List<TrustListEntry>): TrustServiceProvider {
        val first = entries.first()
        val base = mapToTrustServiceProvider(first)
        return base.copy(tspServices = entries.map { TSPServices(tspService = mapToTspService(it)) })
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

        val tspServices = listOf(TSPServices(tspService = mapToTspService(entry)))

        return TrustServiceProvider(tspInformation = tspInformation, tspServices = tspServices)
    }

    /** Maps one entry's `service` section (plus its accreditation) onto a [TSPService]. */
    private fun mapToTspService(entry: TrustListEntry): TSPService {
        val service = entry.service
        val cert = service?.digitalIdentity?.firstOrNull()
            ?.replace(Regex("\\s"), "")
            ?.takeIf { it.isNotBlank() }
        val matchedIndex = entry.matchedCertIndex ?: 0
        val subjectKeyIdentifier = entry.certificateDetails?.getOrNull(matchedIndex)?.subjectKeyIdentifier
            ?: entry.certificateDetails?.firstOrNull()?.subjectKeyIdentifier

        val did = service?.did?.takeIf { it.isNotBlank() }
        val kid = service?.kid?.takeIf { it.isNotBlank() }
        val jwksURI = service?.jwksURI?.takeIf { it.isNotBlank() }

        val hasIdentity =
            cert != null || subjectKeyIdentifier != null || did != null || kid != null || jwksURI != null

        val serviceDigitalIdentity = if (hasIdentity) {
            ServiceDigitalIdentity(
                digitalId = DigitalId(
                    x509Certificate = cert,
                    x509SKI = subjectKeyIdentifier,
                    did = did,
                    kid = kid,
                    jwksURI = jwksURI
                )
            )
        } else {
            null
        }
        val serviceInformation = ServiceInformation(
            serviceTypeIdentifier = service?.serviceTypeIdentifier,
            serviceName = service?.serviceName?.let { SchemeOperatorName(name = LangValue(value = it)) },
            serviceStatus = service?.serviceStatus,
            statusStartingTime = service?.statusStartingTime,
            serviceDigitalIdentity = serviceDigitalIdentity,
            permittedCredentials = entry.permittedCredentials,
            prohibitedCredentials = entry.prohibitedCredentials
        )
        return TSPService(serviceInformation = serviceInformation)
    }
}
