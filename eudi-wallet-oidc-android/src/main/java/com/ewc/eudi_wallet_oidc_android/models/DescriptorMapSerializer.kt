package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.*
import java.lang.reflect.Type

class DescriptorMapSerializer : JsonSerializer<DescriptorMap> {
    override fun serialize(
        src: DescriptorMap?, typeOfSrc: Type?, context: JsonSerializationContext?
    ): JsonElement {
        val jsonObject = JsonObject()

        // Add basic fields, but only if they are not null
        src?.id?.let { jsonObject.add("id", JsonPrimitive(it)) }
        src?.path?.let { jsonObject.add("path", JsonPrimitive(it)) }
        src?.format?.let { jsonObject.add("format", JsonPrimitive(it)) }

        // Only add pathNested if it's not null
        if (src?.pathNested != null) {
            val pathNestedJson = JsonObject()
            src.pathNested?.id?.let { pathNestedJson.add("id", JsonPrimitive(it)) }
            src.pathNested?.path?.let { pathNestedJson.add("path", JsonPrimitive(it)) }
            src.pathNested?.format?.let { pathNestedJson.add("format", JsonPrimitive(it)) }
            jsonObject.add("path_nested", pathNestedJson)
        }

        return jsonObject
    }
}
