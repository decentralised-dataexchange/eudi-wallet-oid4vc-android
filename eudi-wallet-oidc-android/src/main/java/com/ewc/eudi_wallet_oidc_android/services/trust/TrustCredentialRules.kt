package com.ewc.eudi_wallet_oidc_android.services.trust

import com.ewc.eudi_wallet_oidc_android.models.TrustCredentialType

/**
 * The credential a trust check is about, matched against a service's permitted / prohibited lists.
 * [vct] applies to SD-JWT VCs, [doctype] to mdoc.
 */
data class TrustCredentialDescriptor(
    val format: String? = null,
    val vct: String? = null,
    val doctype: String? = null
) {
    val debugDescription: String get() = "${format ?: "-"}/${vct ?: doctype ?: "?"}"

    /** True when neither the type nor the format is known — the rules cannot be evaluated. */
    val isEmpty: Boolean
        get() = format.isNullOrBlank() && vct.isNullOrBlank() && doctype.isNullOrBlank()
}

/** Outcome of applying a service's permitted / prohibited credential lists. */
sealed class TrustCredentialDecision {
    object Allowed : TrustCredentialDecision()
    data class Prohibited(val rule: TrustCredentialType) : TrustCredentialDecision()
    data class NotPermitted(val allowList: List<TrustCredentialType>) : TrustCredentialDecision()

    /** The service carries rules but the credential could not be identified, so they were skipped. */
    object NotEvaluated : TrustCredentialDecision()
}

/**
 * Applies a service's `permittedCredentials` (allow-list) and `prohibitedCredentials` (deny-list)
 * to the credential in play.
 *
 * Rules, in order:
 * 1. prohibited is non-empty and the credential matches one → refused
 * 2. permitted is non-empty and the credential matches none → refused
 * 3. otherwise allowed (both lists empty ⇒ no credential restriction)
 */
object TrustCredentialRules {

    /**
     * What to do when the credential cannot be identified but the service carries rules.
     * `false` (current) = skip the check and log loudly; `true` = fail closed.
     */
    var denyWhenCredentialUnknown = false

    fun evaluate(
        descriptor: TrustCredentialDescriptor?,
        permitted: List<TrustCredentialType>,
        prohibited: List<TrustCredentialType>
    ): TrustCredentialDecision {
        if (permitted.isEmpty() && prohibited.isEmpty()) return TrustCredentialDecision.Allowed

        if (descriptor == null || descriptor.isEmpty) {
            return if (denyWhenCredentialUnknown) {
                TrustCredentialDecision.NotPermitted(permitted)
            } else {
                TrustCredentialDecision.NotEvaluated
            }
        }

        prohibited.firstOrNull { matches(descriptor, it) }?.let {
            return TrustCredentialDecision.Prohibited(it)
        }
        if (permitted.isNotEmpty() && permitted.none { matches(descriptor, it) }) {
            return TrustCredentialDecision.NotPermitted(permitted)
        }
        return TrustCredentialDecision.Allowed
    }

    /**
     * A rule matches when the formats agree AND, if the rule names a `vct`/`doctype`, that agrees
     * too. A rule with only a format matches every credential of that format.
     */
    fun matches(descriptor: TrustCredentialDescriptor, rule: TrustCredentialType): Boolean {
        val ruleFormat = normalise(rule.format)
        val credentialFormat = normalise(descriptor.format)
        if (ruleFormat != null && credentialFormat != null && ruleFormat != credentialFormat) {
            return false
        }
        rule.vct?.takeIf { it.isNotBlank() }?.let { ruleVct ->
            return descriptor.vct?.takeIf { it.isNotBlank() }?.equals(ruleVct, ignoreCase = true) == true
        }
        rule.doctype?.takeIf { it.isNotBlank() }?.let { ruleDoctype ->
            return descriptor.doctype?.takeIf { it.isNotBlank() }?.equals(ruleDoctype, ignoreCase = true) == true
        }
        // Format-only rule: it matched above (or neither side declared a format).
        return rule.format != null
    }

    /**
     * `dc+sd-jwt` and `vc+sd-jwt` are the new and old names of the same format; a rule written for
     * one must apply to a credential labelled the other, otherwise a PID prohibition silently fails.
     */
    private fun normalise(format: String?): String? {
        val value = format?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: return null
        return when (value) {
            "dc+sd-jwt", "vc+sd-jwt", "sd-jwt", "sd_jwt", "vc+sd-jwt-vc" -> "sd-jwt"
            "mso_mdoc", "mso-mdoc", "mdoc" -> "mso_mdoc"
            else -> value
        }
    }
}
