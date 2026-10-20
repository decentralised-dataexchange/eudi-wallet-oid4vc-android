package com.ewc.eudi_wallet_oidc_android.services.verification.vpTokenBuilders

import android.util.Base64
import com.ewc.eudi_wallet_oidc_android.models.CredentialList
import com.ewc.eudi_wallet_oidc_android.models.InputDescriptors
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.utils.generateHash
import org.json.JSONObject
import java.nio.charset.StandardCharsets

/**
 * The transaction data rules of the previous API, kept while the response path is rebuilt: only
 * the first `transaction_data` entry is considered, and strong customer authentication is
 * detected from its type. The transaction data leg replaces both.
 */
internal object LegacyTransactionData {

    /** The hash of the first entry when its `credential_ids` names [entry], else nothing. */
    fun hashesFor(entry: Any?, request: PresentationRequest?): List<String> {
        val first = request?.transactionDdata?.firstOrNull() ?: return emptyList()
        val id = when (entry) {
            is InputDescriptors -> entry.id
            is CredentialList -> entry.id
            else -> null
        } ?: return emptyList()
        return try {
            val json = JSONObject(String(Base64.decode(first, Base64.URL_SAFE), StandardCharsets.UTF_8))
            val ids = json.optJSONArray("credential_ids")?.let { array -> List(array.length()) { array.getString(it) } }.orEmpty()
            if (id in ids) listOfNotNull(generateHash(first)) else emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }

    /**
     * True only for the TS12 strong customer authentication transaction data types (payment,
     * login_risk, account_access, emandate), as a URN or as an HTTPS transaction-data-type URL.
     * False for the EWC `payment_data` and the QES types, which must not carry `response_mode`
     * and `amr` in the key binding JWT.
     */
    fun isStrongCustomerAuthentication(request: PresentationRequest?): Boolean {
        val first = request?.transactionDdata?.firstOrNull() ?: return false
        return try {
            val type = JSONObject(String(Base64.decode(first, Base64.URL_SAFE), StandardCharsets.UTF_8)).optString("type", "")
            type.contains("urn:eudi:sca:") ||
                type.contains("transaction-data-type/payment") ||
                type.contains("transaction-data-type/login_risk") ||
                type.contains("transaction-data-type/account_access") ||
                type.contains("transaction-data-type/emandate")
        } catch (e: Exception) {
            false
        }
    }
}
