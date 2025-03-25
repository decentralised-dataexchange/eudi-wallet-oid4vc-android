package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

data class NotificationRequest(

    @SerializedName("notification_id") var notificationId: String? = null,
    @SerializedName("event") var event: String? = null,

    )