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
}

class PayloadPayee {

    @SerializedName("id")
    @Expose
    var id: String? = null

    @SerializedName("name")
    @Expose
    var name: String? = null
}
