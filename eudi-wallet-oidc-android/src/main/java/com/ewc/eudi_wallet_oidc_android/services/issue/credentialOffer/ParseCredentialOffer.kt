package com.ewc.eudi_wallet_oidc_android.services.issue.credentialOffer

import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.v1.CredentialOfferEbsiV1
import com.ewc.eudi_wallet_oidc_android.models.v1.CredentialOfferEwcV1
import com.ewc.eudi_wallet_oidc_android.models.v2.CredentialOfferEwcV2
import com.google.gson.Gson

class ParseCredentialOffer {
    fun parse(credentialOfferJson: String?): CredentialOffer? {
        val gson = Gson()
        val credentialOfferV2Response = try {
            gson.fromJson(credentialOfferJson, CredentialOfferEwcV2::class.java)
        } catch (e: Exception) {
            null
        }
        if (credentialOfferV2Response?.credentialConfigurationIds == null) {
            val credentialOfferEbsiV1Response = try {
                gson.fromJson(credentialOfferJson, CredentialOfferEbsiV1::class.java)
            } catch (e: Exception) {
                null
            }
            return if (credentialOfferEbsiV1Response?.credentials == null) {
                val credentialOfferEwcV1Response = try {
                    gson.fromJson(credentialOfferJson, CredentialOfferEwcV1::class.java)
                } catch (e: Exception) {
                    null
                }
                if (credentialOfferEwcV1Response == null) {
                    null
                } else {
                    CredentialOffer(ewcV1 = credentialOfferEwcV1Response)
                }
            } else {
                credentialOfferEbsiV1Response?.let { CredentialOffer(ebsiV1 = it) }
            }
        } else {
            return CredentialOffer(ewcV2 = credentialOfferV2Response)
        }
    }
}