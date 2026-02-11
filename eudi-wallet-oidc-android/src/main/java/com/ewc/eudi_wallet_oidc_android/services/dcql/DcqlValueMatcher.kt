package com.ewc.eudi_wallet_oidc_android.services.dcql

import com.ewc.eudi_wallet_oidc_android.models.DcqlClaim

object DcqlValueMatcher {

    fun matchesClaimValues(claim: DcqlClaim, actualValue: Any?): Boolean {
        val expectedValues = claim.values
        if (expectedValues.isNullOrEmpty()) return true

        return when (actualValue) {

            is List<*> -> {
                actualValue.any { element ->
                    expectedValues.any { expected ->
                        when {
                            expected is Number && element is Number ->
                                expected.toDouble() == element.toDouble()

                            else ->
                                expected == element &&
                                        expected?.javaClass == element?.javaClass
                        }
                    }
                }
            }

            else -> {
                expectedValues.any { expected ->
                    when {
                        expected is Number && actualValue is Number ->
                            expected.toDouble() == actualValue.toDouble()

                        else ->
                            expected == actualValue &&
                                    expected?.javaClass == actualValue?.javaClass
                    }
                }
            }
        }
    }
}
