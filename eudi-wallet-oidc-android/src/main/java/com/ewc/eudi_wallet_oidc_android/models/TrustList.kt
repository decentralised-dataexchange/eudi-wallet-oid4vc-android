package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.JsonElement
import com.google.gson.annotations.SerializedName

/**
 * Payload models for the OWS Trust List backend (open lookup endpoint) used by
 * [com.ewc.eudi_wallet_oidc_android.services.trust.ServerTrustMechanismService].
 *
 * Endpoint: POST {baseUrl}/trust-list/lookup -> lookup by x5c / kid / did / jwksUri.
 */
/**
 * Lookup body: send the identifier the verifier/issuer is known by — the certificate chain
 * ([x5c], primary path), its key id ([kid]), its DID ([did]), or its JWKS URI ([jwksUri]). Exactly
 * one is populated.
 */
data class TrustListLookupRequest(
    @SerializedName("x5c")
    val x5c: List<String>? = null,

    @SerializedName("kid")
    val kid: String? = null,

    @SerializedName("did")
    val did: String? = null,

    @SerializedName("jwksUri")
    val jwksUri: String? = null
)

/**
 * Status of a matched trust-list service. Only [GRANTED] is trusted; everything else — including a
 * status that cannot be parsed — is refused (fail-closed).
 *
 * The raw value is an ETSI URI whose last path segment carries the meaning, e.g.
 * `https://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted/`. Scheme (http/https), letter case
 * and the trailing slash all vary between trust lists, so only that last segment is compared.
 */
enum class TrustServiceStatus {
    GRANTED,

    /**
     * The WRPAC provider lists (`…/19602/WRPACProvidersList/SvcStatus/notified`) use `notified`
     * where the ETSI trusted lists use `granted`. Treated as granted-equivalent — see [isTrusted].
     */
    NOTIFIED,
    WITHDRAWN,
    UNKNOWN;

    /** Only these statuses are trusted; anything else, including unparseable, is refused. */
    val isTrusted: Boolean get() = this == GRANTED || this == NOTIFIED

    companion object {
        fun from(rawValue: String?): TrustServiceStatus {
            val raw = rawValue?.trim()?.lowercase().orEmpty()
            if (raw.isEmpty()) return UNKNOWN
            val segment = raw.trimEnd('/').substringAfterLast('/')
            return when (segment) {
                "granted" -> GRANTED
                "notified" -> NOTIFIED
                "withdrawn" -> WITHDRAWN
                else -> UNKNOWN
            }
        }
    }
}

/**
 * One credential type in a service's permitted / prohibited list, e.g.
 * `{"format": "dc+sd-jwt", "vct": "urn:eudi:pid:1"}` or
 * `{"format": "mso_mdoc", "doctype": "eu.europa.ec.eudi.pid.1"}`.
 */
data class TrustCredentialType(
    @SerializedName("format")
    val format: String? = null,

    @SerializedName("vct")
    val vct: String? = null,

    @SerializedName("doctype")
    val doctype: String? = null
) {
    /** Human-readable form for logs. */
    val debugDescription: String get() = "${format ?: "-"}/${vct ?: doctype ?: "*"}"
}

data class TrustListLookupResponse(
    @SerializedName("match")
    val match: Boolean = false,

    /** Current response shape: every trust-list service the identifier matched. */
    @SerializedName("entries")
    val entries: List<TrustListEntry>? = null,

    /** Legacy response shape: a single matched entry. Kept so an older backend still parses. */
    @SerializedName("entry")
    val entry: TrustListEntry? = null
) {
    /**
     * All matched entries, whichever shape the backend returned — including withdrawn ones.
     * Use [grantedEntries] for any trust decision.
     */
    val matchedEntries: List<TrustListEntry>
        get() = entries?.takeIf { it.isNotEmpty() } ?: listOfNotNull(entry)

    /**
     * Matched entries whose service status is granted. An identifier can be granted in one trust
     * list and withdrawn in another, so this filters per entry rather than rejecting the response.
     */
    val grantedEntries: List<TrustListEntry>
        get() = matchedEntries.filter { it.serviceStatusValue.isTrusted }
}

data class TrustListEntry(
    @SerializedName("status")
    val status: String? = null,

    @SerializedName("provider")
    val provider: TrustListProvider? = null,

    @SerializedName("service")
    val service: TrustListService? = null,

    @SerializedName("certificateDetails")
    val certificateDetails: List<TrustListCertDetail>? = null,

    @SerializedName("matchedCertIndex")
    val matchedCertIndex: Int? = null,

    @SerializedName("trustList")
    val trustList: TrustListInfo? = null,

    /**
     * Allow-list: when non-empty, ONLY these credential types may be issued/requested by this
     * service. Held as a raw [JsonElement] because the field changed shape once already (an object,
     * now a list) — a strict binding would fail the WHOLE response, and a response that fails to
     * parse means every organisation is untrusted.
     */
    @SerializedName("permittedCredentials")
    val permittedCredentialsRaw: JsonElement? = null,

    /** Deny-list: a credential matching any of these is refused even when role and status pass. */
    @SerializedName("prohibitedCredentials")
    val prohibitedCredentialsRaw: JsonElement? = null
) {
    val permittedCredentials: List<TrustCredentialType> get() = parseCredentialTypes(permittedCredentialsRaw)
    val prohibitedCredentials: List<TrustCredentialType> get() = parseCredentialTypes(prohibitedCredentialsRaw)

    private fun parseCredentialTypes(element: JsonElement?): List<TrustCredentialType> {
        val array = element?.takeIf { it.isJsonArray }?.asJsonArray ?: return emptyList()
        return array.mapNotNull { item ->
            val obj = item?.takeIf { it.isJsonObject }?.asJsonObject ?: return@mapNotNull null
            fun str(key: String) = obj.get(key)?.takeIf { it.isJsonPrimitive }?.asString?.takeIf { it.isNotBlank() }
            TrustCredentialType(format = str("format"), vct = str("vct"), doctype = str("doctype"))
        }
    }

    /**
     * Status of this entry's service. Reads the service-level `serviceStatus` URI, falling back to
     * the entry-level `status`; UNKNOWN when neither is present or parseable.
     */
    val serviceStatusValue: TrustServiceStatus
        get() = TrustServiceStatus.from(service?.serviceStatus)
            .takeIf { it != TrustServiceStatus.UNKNOWN }
            ?: TrustServiceStatus.from(status)
}

data class TrustListInfo(
    @SerializedName("name")
    val name: String? = null,

    @SerializedName("url")
    val url: String? = null,

    @SerializedName("schemeName")
    val schemeName: String? = null
)

data class TrustListCertDetail(
    @SerializedName("subjectKeyIdentifier")
    val subjectKeyIdentifier: String? = null,

    @SerializedName("sha256Fingerprint")
    val sha256Fingerprint: String? = null
)

data class TrustListProvider(
    @SerializedName("tSPName")
    val tSPName: String? = null,

    @SerializedName("tSPTradeName")
    val tSPTradeName: String? = null,

    @SerializedName("streetAddress")
    val streetAddress: String? = null,

    @SerializedName("locality")
    val locality: String? = null,

    @SerializedName("postalCode")
    val postalCode: String? = null,

    @SerializedName("countryName")
    val countryName: String? = null,

    @SerializedName("electronicAddress")
    val electronicAddress: String? = null,

    @SerializedName("tSPInformationURI")
    val tSPInformationURI: String? = null
)

data class TrustListService(
    @SerializedName("serviceTypeIdentifier")
    val serviceTypeIdentifier: String? = null,

    @SerializedName("serviceStatus")
    val serviceStatus: String? = null,

    @SerializedName("statusStartingTime")
    val statusStartingTime: String? = null,

    @SerializedName("serviceName")
    val serviceName: String? = null,

    @SerializedName("did")
    val did: String? = null,

    @SerializedName("kid")
    val kid: String? = null,

    @SerializedName("jwksURI")
    val jwksURI: String? = null,

    /** Legacy: some responses may still return the cert chain here. */
    @SerializedName("digitalIdentity")
    val digitalIdentity: List<String>? = null
)
