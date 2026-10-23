package com.ewc.eudi_wallet_oidc_android.services.verification.match

import com.google.gson.JsonElement
import com.google.gson.JsonNull
import com.google.gson.JsonPrimitive

/**
 * OpenID4VP 1.0 section 7, claims path pointer processing.
 *
 * "A string value indicates that the respective key is to be selected, a null value indicates
 * that all elements of the currently selected array(s) are to be selected; and a non-negative
 * integer indicates that the respective index in an array is to be selected." The pointer arrives
 * through a `List<String?>`, so an integer component is a string of digits applied to an array.
 *
 * For an mdoc (section 7.2) the pointer is `[namespace, element]` over the JSON the namespaces
 * were converted to, which the same walk covers.
 */
object ClaimsPathPointer {

    /**
     * The selected elements, or null when processing aborts under section 7.1.1: a key applied to
     * something that is not an object, `null` or an index applied to something that is not an
     * array, or an empty selection.
     */
    fun select(root: JsonElement, path: List<String?>): List<JsonElement>? {
        if (path.isEmpty()) return null
        var selected: List<JsonElement> = listOf(root)
        for (component in path) {
            val next = mutableListOf<JsonElement>()
            for (element in selected) {
                when {
                    component == null -> {
                        if (!element.isJsonArray) return null
                        element.asJsonArray.forEach { next.add(it) }
                    }
                    element.isJsonArray && component.all { it.isDigit() } -> {
                        val index = component.toInt()
                        if (index < element.asJsonArray.size()) next.add(element.asJsonArray[index])
                    }
                    element.isJsonObject -> {
                        element.asJsonObject.get(component)?.let { next.add(it) }
                    }
                    else -> return null
                }
            }
            if (next.isEmpty()) return null
            selected = next
        }
        return selected
    }

    /** The selected elements as plain values: String, Number, Boolean, List, Map or null. */
    fun selectValues(root: JsonElement, path: List<String?>): List<Any?>? =
        select(root, path)?.map { toValue(it) }

    fun toValue(element: JsonElement): Any? = when {
        element.isJsonNull || element is JsonNull -> null
        element.isJsonPrimitive -> {
            val p = element as JsonPrimitive
            when {
                p.isBoolean -> p.asBoolean
                p.isNumber -> p.asNumber.let { n -> if (n.toString().contains('.')) n.toDouble() else n.toLong() }
                else -> p.asString
            }
        }
        element.isJsonArray -> element.asJsonArray.map { toValue(it) }
        else -> element.asJsonObject.entrySet().associate { it.key to toValue(it.value) }
    }
}
