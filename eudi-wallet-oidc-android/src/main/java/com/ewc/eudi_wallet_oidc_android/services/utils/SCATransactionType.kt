package com.ewc.eudi_wallet_oidc_android.services.utils

enum class SCATransactionType(val type: String) {
    PAYMENT("urn:eudi:sca:payment:1"),
    LOGIN_RISK("urn:eudi:sca:login_risk_transaction:1");

    companion object {
        fun isPayment(type: String?) = type == PAYMENT.type
        fun isLoginRisk(type: String?) = type == LOGIN_RISK.type
        fun isValidScaType(type: String?): Boolean {
            return entries.any { it.type == type }
        }
    }
}