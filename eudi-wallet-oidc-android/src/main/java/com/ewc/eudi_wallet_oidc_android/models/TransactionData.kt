package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.Expose
import com.google.gson.annotations.SerializedName

class TransactionData {

    @SerializedName("credential_ids")
    @Expose
    var credentialIds: List<String>? = null

    @SerializedName("payment_data")
    @Expose
    var paymentData: PaymentData? = null

    @SerializedName("payload")
    @Expose
    var payload: Payload? = null

    @SerializedName("transaction_data_hashes_alg")
    @Expose
    var transactionDataHashesAlg: Any? = null

    @SerializedName("type")
    @Expose
    var type: String? = null
}


class PaymentData {

    @SerializedName("currency_amount")
    @Expose
    var currencyAmount: CurrencyAmount? = null

    @SerializedName("payee")
    @Expose
    var payee: String? = null
}

class CurrencyAmount {

    @SerializedName("currency")
    @Expose
    var currency: String? = null

    @SerializedName("value")
    @Expose
    var value: Double? = null
}

class Payload {

    // 🔹 PAYMENT FIELDS
    @SerializedName("amount")
    @Expose
    var amount: Double? = null


    @SerializedName("currency")
    @Expose
    var currency: String? = null

    @SerializedName("date_time")
    @Expose
    var dateTime: String? = null

    @SerializedName("transaction_id")
    @Expose
    var transactionId: String? = null

    @SerializedName("payee")
    @Expose
    var payee: PayloadPayee? = null

    @SerializedName("action")
    @Expose
    var action: String? = null

    @SerializedName("service")
    @Expose
    var service: String? = null

    @SerializedName("start_date")
    @Expose
    var startDate: String? = null

    @SerializedName("end_date")
    @Expose
    var endDate: String? = null

    @SerializedName("reference_number")
    @Expose
    var referenceNumber: String? = null

    @SerializedName("creditor_id")
    @Expose
    var creditorId: String? = null

    @SerializedName("purpose")
    @Expose
    var purpose: String? = null

    @SerializedName("payment_payload")
    @Expose
    var paymentPayload: PaymentPayload? = null

    @SerializedName("execution_date")
    @Expose
    var executionDate: String? = null

    @SerializedName("amount_estimated")
    @Expose
    var amountEstimated: Boolean? = null

    @SerializedName("amount_earmarked")
    @Expose
    var amountEarmarked: Boolean? = null

    @SerializedName("sct_inst")
    @Expose
    var sctInst: Boolean? = null

    @SerializedName("pisp")
    @Expose
    var pisp: Pisp? = null

    @SerializedName("recurrence")
    @Expose
    var recurrence: Recurrence? = null
}

class PayloadPayee {

    @SerializedName("id")
    @Expose
    var id: String? = null

    @SerializedName("name")
    @Expose
    var name: String? = null
    @SerializedName("logo")
    @Expose
    var logo: String? = null

    @SerializedName("website")
    @Expose
    var website: String? = null
}

class PaymentPayload {
    @SerializedName("transaction_id")
    @Expose
    var transactionId: String? = null

    @SerializedName("date_time")
    @Expose
    var dateTime: String? = null

    @SerializedName("payee")
    @Expose
    var payee: PayloadPayee? = null

    @SerializedName("pisp")
    @Expose
    var pisp: Pisp? = null

    @SerializedName("execution_date")
    @Expose
    var executionDate: String? = null

    @SerializedName("currency")
    @Expose
    var currency: String? = null

    @SerializedName("amount")
    @Expose
    var amount: Double? = null

    @SerializedName("amount_estimated")
    @Expose
    var amountEstimated: Boolean? = null

    @SerializedName("amount_earmarked")
    @Expose
    var amountEarmarked: Boolean? = null

    @SerializedName("sct_inst")
    @Expose
    var sctInst: Boolean? = null

    @SerializedName("recurrence")
    @Expose
    var recurrence: Recurrence? = null
}

class Pisp {
    @SerializedName("legal_name")
    @Expose
    var legalName: String? = null

    @SerializedName("brand_name")
    @Expose
    var brandName: String? = null

    @SerializedName("domain_name")
    @Expose
    var domainName: String? = null
}
class Recurrence {
    @SerializedName("frequency")
    @Expose
    var frequency: String? = null

    @SerializedName("start_date")
    @Expose
    var startDate: String? = null

    @SerializedName("end_date")
    @Expose
    var endDate: String? = null

    @SerializedName("number")
    @Expose
    var number: Int? = null

    @SerializedName("mit_options")
    @Expose
    var mitOptions: MitOptions? = null
}

class MitOptions {
    @SerializedName("amount_variable")
    @Expose
    var amountVariable: Boolean? = null

    @SerializedName("min_amount")
    @Expose
    var minAmount: Double? = null

    @SerializedName("max_amount")
    @Expose
    var maxAmount: Double? = null

    @SerializedName("total_amount")
    @Expose
    var totalAmount: Double? = null

    @SerializedName("initial_amount")
    @Expose
    var initialAmount: Double? = null

    @SerializedName("initial_amount_number")
    @Expose
    var initialAmountNumber: Int? = null

    @SerializedName("apr")
    @Expose
    var apr: Double? = null
}
