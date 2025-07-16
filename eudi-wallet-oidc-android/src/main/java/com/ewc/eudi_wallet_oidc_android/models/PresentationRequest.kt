package com.ewc.eudi_wallet_oidc_android.models
import com.google.gson.annotations.SerializedName
data class ClientMetaDetails(
    @SerializedName("client_name") var clientName: String? = null,
    @SerializedName("cover_uri") var coverUri: String? = null,
    @SerializedName("description") var description: String? = null,
    @SerializedName("location") var location: String? = null,
    @SerializedName("logo_uri") var logoUri: String? = null,
    @SerializedName("legal_pid_attestation") var legalPidAttestation: String? = null,
    @SerializedName("legal_pid_attestation_pop") var legalPidAttestationPop: String? = null,
)
data class PresentationRequest(
    @SerializedName("state") var state: String? = null,
    @SerializedName("client_id") var clientId: String? = null,
    @SerializedName("redirect_uri") var redirectUri: String? = null,
    @SerializedName("response_type") var responseType: String? = null,
    @SerializedName("response_mode") var responseMode: String? = null,
    @SerializedName("scope") var scope: String? = null,
    @SerializedName("nonce") var nonce: String? = null,
    @SerializedName("request_uri") var requestUri: String? = null,
    @SerializedName("response_uri") var responseUri: String? = null,
    @SerializedName("presentation_definition") var presentationDefinition: Any? = null,
    @SerializedName("presentation_definition_uri") var presentationDefinitionUri: String? = null,
    @SerializedName("client_metadata") var clientMetaDetails: Any? = null,
    @SerializedName("client_metadata_uri") var clientMetadataUri: String? = null,
    @SerializedName("client_id_scheme") var clientIdScheme: String? = null,
    @SerializedName("transaction_data") var transactionDdata: ArrayList<String>? = null,
    @SerializedName("request") var request: String? = null,
    @SerializedName("dcql_query") var dcqlQuery: DCQL? = null,

    )
data class DCQL(
    @SerializedName("credentials") var credentials: List<CredentialList>? = null,
    val credential_sets: List<CredentialSet>? = null // Optional, since the second example doesn't include it
)

data class CredentialList(
    @SerializedName("id") var id: String? = null,
    @SerializedName("format") var format: String? = null,
    @SerializedName("meta") var meta: Meta? = null,
    val claims: List<DcqlClaim>,
    val claim_sets: List<List<String>>? = null // Only present in dc+sd-jwt format
)

data class Meta(
    @SerializedName("vct_values") var vctValues: ArrayList<String>? = null,
    @SerializedName("doctype_value") var doctypeValue: String? = null,
    @SerializedName("type_values") var typeValues: List<List<String>>? = null
)

data class DcqlClaim(
    val id: String?=null,
    @SerializedName("path") val path: List<String>? = null,
    @SerializedName("namespace") val namespace: String? = null,
    @SerializedName("claim_name") val claimName: String? = null
)
data class CredentialSet(
    val purpose: String?=null,
    val required: Boolean = true,
    val options: List<List<String>>? = null
)
data class WrappedPresentationRequest(
    var presentationRequest: PresentationRequest?=null,
    var errorResponse: ErrorResponse? = null
)