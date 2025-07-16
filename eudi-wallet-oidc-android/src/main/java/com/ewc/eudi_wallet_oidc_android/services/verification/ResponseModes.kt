package com.ewc.eudi_wallet_oidc_android.services.verification

enum class ResponseModes(val value: String) {

    DIRECT_POST("direct_post"),

    DIRECT_POST_JWT("direct_post.jwt"),

    DC_API("dc_api"),

    DC_API_JWT("dc_api.jwt");

    companion object {
        /**
         * Converts a string value to its corresponding [ResponseModes].
         *
         * @param value The string value to convert.
         * @return The matching [ResponseModes], or null if no match is found.
         */
        fun fromString(value: String): ResponseModes? =
            values().find { it.value == value }
    }
}