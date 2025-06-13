package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

data class Root(
    @SerializedName("TSLTag")
    var tslTag: String? = null,

    @SerializedName("SchemeInformation")
    var schemeInformation: SchemeInformation? = null,

    @SerializedName("TrustServiceProviderList")
    var trustServiceProviderList: TrustServiceProviderList? = null
)

data class SchemeInformation(
    @SerializedName("TSLVersionIdentifier")
    var tslVersionIdentifier: String? = null,

    @SerializedName("TSLSequenceNumber")
    var tslSequenceNumber: String? = null,

    @SerializedName("TSLType")
    var tslType: String? = null,

    @SerializedName("SchemeOperatorName")
    var schemeOperatorName: SchemeOperatorName? = null,

    @SerializedName("SchemeOperatorAddress")
    var schemeOperatorAddress: SchemeOperatorAddress? = null,

    @SerializedName("SchemeName")
    var schemeName: SchemeName? = null,

    @SerializedName("SchemeInformationURI")
    var schemeInformationURI: String? = null,

    @SerializedName("StatusDeterminationApproach")
    var statusDeterminationApproach: String? = null,

    @SerializedName("SchemeTypeCommunityRules")
    var schemeTypeCommunityRules: SchemeTypeCommunityRules? = null,

    @SerializedName("SchemeTerritory")
    var schemeTerritory: String? = null,

    @SerializedName("PolicyOrLegalNotice")
    var policyOrLegalNotice: String? = null,

    @SerializedName("HistoricalInformationPeriod")
    var historicalInformationPeriod: String? = null,

    @SerializedName("PointersToOtherTSL")
    var pointersToOtherTSL: String? = null,

    @SerializedName("ListIssueDateTime")
    var listIssueDateTime: String? = null,

    @SerializedName("NextUpdate")
    var nextUpdate: NextUpdate? = null
)

data class SchemeOperatorName(
    @SerializedName("Name")
    var name: LangValue? = null
)

data class SchemeOperatorAddress(
    @SerializedName("PostalAddresses")
    var postalAddresses: PostalAddresses? = null,

    @SerializedName("ElectronicAddress")
    var electronicAddress: ElectronicAddress? = null
)

data class PostalAddresses(
    @SerializedName("PostalAddress")
    var postalAddress: PostalAddress? = null
)

data class PostalAddress(
    @SerializedName("lang")
    var lang: String? = null,

    @SerializedName("StreetAddress")
    var streetAddress: String? = null,

    @SerializedName("Locality")
    var locality: String? = null,

    @SerializedName("PostalCode")
    var postalCode: String? = null,

    @SerializedName("CountryName")
    var countryName: String? = null,

    @SerializedName("StateOrProvince")
    var stateOrProvince: String? = null
)

data class ElectronicAddress(
    @SerializedName("URI")
    var uri: LangValue? = null
)

data class SchemeName(
    @SerializedName("Name")
    var name: LangValue? = null
)

data class SchemeTypeCommunityRules(
    @SerializedName("URI")
    var uri: LangValue? = null
)

data class NextUpdate(
    @SerializedName("dateTime")
    var dateTime: String? = null
)

data class LangValue(
    @SerializedName("lang")
    var lang: String? = null,

    @SerializedName("")
    var value: String? = null
)

data class TrustServiceProviderList(
    @SerializedName("TrustServiceProvider")
    var trustServiceProvider: List<TrustServiceProvider>? = null
)

data class TrustServiceProvider(
    @SerializedName("TSPInformation")
    var tspInformation: TSPInformation? = null,

    @SerializedName("TSPServices")
    var tspServices: TSPServices? = null
)

data class TSPInformation(
    @SerializedName("TSPName")
    var tspName: Any? = null,

    @SerializedName("TSPTradeName")
    var tspTradeName: SchemeOperatorName? = null,

    @SerializedName("TSPAddress")
    var tspAddress: SchemeOperatorAddress? = null,

    @SerializedName("TSPInformationURI")
    var tspInformationURI: Any? = null
)

data class TSPServices(
    @SerializedName("TSPService")
    var tspService: Any? = null
)

data class TSPService(
    @SerializedName("ServiceInformation")
    var serviceInformation: Any? = null
)

data class ServiceInformation(
    @SerializedName("ServiceTypeIdentifier")
    var serviceTypeIdentifier: String? = null,

    @SerializedName("ServiceName")
    var serviceName: SchemeOperatorName? = null,

    @SerializedName("ServiceDigitalIdentity")
    var serviceDigitalIdentity: ServiceDigitalIdentity? = null,

    @SerializedName("ServiceStatus")
    var serviceStatus: String? = null,

    @SerializedName("StatusStartingTime")
    var statusStartingTime: String? = null
)

data class ServiceDigitalIdentity(
    @SerializedName("DigitalId")
    var digitalId: Any? = null
)

data class DigitalId(
    @SerializedName("X509Certificate")
    var x509Certificate: String? = null,

    @SerializedName("X509SKI")
    var x509SKI: String? = null
)

