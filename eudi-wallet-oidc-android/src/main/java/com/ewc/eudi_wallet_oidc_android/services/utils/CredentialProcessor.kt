package com.ewc.eudi_wallet_oidc_android.services.utils

import android.util.Base64
import com.ewc.eudi_wallet_oidc_android.services.sdjwt.SDJWTService
import org.json.JSONObject

object CredentialProcessor {
    fun splitCredentialsBySdJWT(
        allCredentials: List<String?>,
        isSdJwt: Boolean?=false
    ): ArrayList<String?> {
//        val filteredCredentials: ArrayList<String?> = arrayListOf()
//        for (item in allCredentials) {
//            if (isSdJwt && item?.contains("~") == true)
//                filteredCredentials.add(item)
//            else if (!isSdJwt && item?.contains("~") == false)
//                filteredCredentials.add(item)
//        }
        return ArrayList(allCredentials)
    }

    fun processCredentialsToJsonString(credentialList: ArrayList<String?>): List<String> {
        var processedCredentials: List<String> = mutableListOf()
        for (cred in credentialList) {
            val split = cred?.split(".")


            val jsonString = if ((split?.size ?: 0) > 1 && (cred?.split("~")?.size ?: 0) > 0)
            //SDJWTService().updateIssuerJwtWithDisclosuresForFiltering(cred)
                SDJWTService().updateIssuerJwtWithDisclosures(cred)
            else if ((split?.size ?: 0) > 1)
                Base64.decode(
                    split?.get(1) ?: "",
                    Base64.URL_SAFE
                ).toString(charset("UTF-8"))
            else
                "{}"
            val json = JSONObject(jsonString ?: "{}")

            // todo known item, we are considering the path from only vc
            processedCredentials =
                processedCredentials + listOf(
                    if (json.has("vc")) json.getJSONObject("vc").toString()
                    else json.toString()
                )
        }
        return processedCredentials
    }
}