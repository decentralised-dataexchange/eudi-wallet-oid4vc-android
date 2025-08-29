package com.ewc.eudi_wallet_oidc_android.services.utils

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest

object CredentialRequirementValidator {

    /**
     * Validates if all mandatory credential sets in the given presentationRequest
     * are satisfied by the credentialList.
     *
     * @param credentialList Nested credential list aligned with dcqlQuery.credentials order
     * @param presentationRequest The DCQL presentation request object
     * @return true if all mandatory sets are satisfied, false otherwise
     */
    fun validate(
        credentialList: List<List<Any?>>,
        presentationRequest: PresentationRequest?
    ): Boolean {
        val credentialSets = presentationRequest?.dcqlQuery?.credential_sets ?: emptyList()
        val credentialsFromDcql = presentationRequest?.dcqlQuery?.credentials ?: emptyList()

        for (set in credentialSets) {
            val isRequired = set.required != false // default = true
            if (!isRequired) continue // skip optional sets

            val optionsList = set.options ?: emptyList()

            // A credential set is satisfied if any of its option groups is satisfied
            val setSatisfied = optionsList.any { optionGroup ->
                optionGroup.any { optionId ->
                    val position = credentialsFromDcql.indexOfFirst { it.id == optionId }
                    if (position == -1) false
                    else {
                        val itemsAtPosition = credentialList.getOrNull(position) ?: emptyList()
                        itemsAtPosition.isNotEmpty()
                    }
                }
            }

            if (!setSatisfied) {
                return false // at least one mandatory set not satisfied
            }
        }
        return true
    }
}