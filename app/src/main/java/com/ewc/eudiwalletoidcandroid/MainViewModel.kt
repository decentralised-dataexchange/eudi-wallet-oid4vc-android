package com.ewc.eudiwalletoidcandroid

import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.services.codeVerifier.CodeVerifierService
import com.ewc.eudi_wallet_oidc_android.services.did.DIDService
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationMode
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationOutcome
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.ewc.eudi_wallet_oidc_android.services.discovery.DiscoveryService
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.DiscoveryException
import com.ewc.eudi_wallet_oidc_android.services.issue.IssueService
import com.nimbusds.jose.jwk.ECKey
import kotlinx.coroutines.launch

/**
 * A harness for the SDK's issuance functions, one at a time.
 *
 * One scan feeds every step; each button invokes exactly one SDK function and prints its result
 * plus **which internal path answered** — the source and spec revision that claimed the offer,
 * which of the two well-known URL layouts the issuer actually serves, whether a non-spec fallback
 * was taken. None of that is visible from the wrapped response the wallet reads, and it is the
 * difference between "this issuer is non-conformant here" and "something is broken".
 *
 * Steps 4 onward are added as each function is reworked.
 */
class MainViewModel : ViewModel() {

    val isLoading = MutableLiveData(false)
    val scannedInput = MutableLiveData("Nothing scanned yet")
    val output = MutableLiveData("")

    private var offer: CredentialOffer? = null
    private var issuerConfig: IssuerWellKnownConfiguration? = null
    private var authConfig: AuthorisationServerWellKnownConfiguration? = null

    private val discoveryService = DiscoveryService()

    // Carried between steps: the token request has to present the same wallet the authorization
    // request did, because its DPoP proof is bound to that key.
    private var wallet: WalletIdentity? = null
    private var codeVerifier: String? = null
    private var authorizationCode: String? = null

    /** The transaction code, when the offer asks for one. Bound two-way to the field in the UI. */
    val txCode = MutableLiveData("")

    fun onScanned(data: String) {
        scannedInput.value = data
        offer = null
        issuerConfig = null
        authConfig = null
        wallet = null
        codeVerifier = null
        authorizationCode = null
        clear()
        log("Scanned", data)
    }

    fun clear() {
        output.value = ""
    }

    /** Step 1 — `IssueService.resolveCredentialOffer`. */
    fun resolveOffer(then: (() -> Unit)? = null) = run("1 · Resolve credential offer") {
        val data = scannedInput.value
        if (data.isNullOrBlank() || data == NOTHING_SCANNED) {
            log("1 · Resolve credential offer", "Scan a credential offer first")
            return@run
        }

        val wrapped = IssueService().resolveCredentialOffer(data)
        val resolved = wrapped.credentialOffer

        if (resolved == null) {
            log("1 · Resolve credential offer", "FAILED\n  ${wrapped.errorResponse?.errorDescription}")
            return@run
        }
        offer = resolved

        log(
            "1 · Resolve credential offer",
            buildString {
                appendLine("  spec revision      ${specVersionOf(resolved)}")
                appendLine("  credential_issuer  ${resolved.credentialIssuer}")
                appendLine("  credentials        ${resolved.credentials?.map { it.types?.lastOrNull() }}")
                appendLine("  formats            ${resolved.credentials?.mapNotNull { it.format }}")
                appendLine("  grants             ${grantsOf(resolved)}")
                append("  tx_code            ${txCodeOf(resolved)}")
            },
        )
        then?.invoke()
    }

    /** Step 2 — `DiscoveryService.getIssuerConfig`. */
    fun discoverIssuer(then: (() -> Unit)? = null) = run("2 · Discover issuer metadata") {
        val issuer = offer?.credentialIssuer
        if (issuer.isNullOrBlank()) {
            log("2 · Discover issuer metadata", "Resolve an offer first")
            return@run
        }

        val result = discoveryService.getIssuerConfigDetailed(issuer)
        val diagnostics = result.diagnostics

        val trace = buildString {
            appendLine("  identifier         ${diagnostics.identifier}")
            appendLine("  urls tried         ${diagnostics.attemptedUrls.size}")
            diagnostics.attemptedUrls.forEach { appendLine("      $it") }
            appendLine("  answered by        ${diagnostics.resolvedUrl ?: "nothing"}")
            appendLine("  url layout         ${layoutOf(diagnostics.form, diagnostics.usedSuffixFallback)}")
            appendLine("  content type       ${diagnostics.contentType}")
            append("  metadata shape     ${diagnostics.specVersion ?: "—"}")
        }

        val config = result.response.issuerConfig
        if (config == null) {
            log("2 · Discover issuer metadata", "FAILED\n  ${result.response.errorResponse?.errorDescription}\n$trace")
            return@run
        }
        issuerConfig = config

        log(
            "2 · Discover issuer metadata",
            buildString {
                appendLine(trace)
                appendLine("  credential_endpoint  ${config.credentialEndpoint}")
                appendLine("  nonce_endpoint       ${config.nonceEndpoint ?: "—"}")
                appendLine("  deferred_endpoint    ${config.deferredCredentialEndpoint ?: "—"}")
                appendLine("  authorization_server ${config.authorizationServer ?: "—"}")
                append("  authorization_servers ${config.authorizationServers ?: "—"}")
            },
        )
        then?.invoke()
    }

    /** Step 3 — `selectAuthorizationServer` then `DiscoveryService.getAuthConfig`. */
    fun discoverAuthServer(then: (() -> Unit)? = null) = run("3 · Discover authorization server") {
        val config = issuerConfig
        if (config == null) {
            log("3 · Discover authorization server", "Discover the issuer metadata first")
            return@run
        }

        val selection = try {
            discoveryService.selectAuthorizationServer(config, offer)
        } catch (e: DiscoveryException) {
            log("3 · Discover authorization server", "STOPPED\n  ${e.message}")
            return@run
        }

        val result = discoveryService.getAuthConfigDetailed(selection.identifier)
        val diagnostics = result.diagnostics

        val trace = buildString {
            appendLine("  selected           ${selection.identifier}")
            appendLine("  chosen because     ${selection.source}")
            appendLine("  candidates         ${selection.candidates}")
            appendLine("  urls tried         ${diagnostics.attemptedUrls.size}")
            diagnostics.attemptedUrls.forEach { appendLine("      $it") }
            appendLine("  answered by        ${diagnostics.resolvedUrl ?: "nothing"}")
            append("  well-known         ${wellKnownOf(diagnostics.wellKnown, diagnostics.usedOpenIdConfigurationFallback)}")
        }

        val auth = result.response.authConfig
        if (auth == null) {
            log("3 · Discover authorization server", "FAILED\n  ${result.response.errorResponse?.errorDescription}\n$trace")
            return@run
        }
        authConfig = auth

        log(
            "3 · Discover authorization server",
            buildString {
                appendLine(trace)
                appendLine("  issuer               ${auth.issuer}")
                appendLine("  authorization_endpoint ${auth.authorizationEndpoint ?: "—"}")
                appendLine("  token_endpoint         ${auth.tokenEndpoint}")
                appendLine("  pushed_auth_endpoint   ${auth.pushedAuthorizationRequestEndpoint ?: "—"}")
                append("  grant_types            ${auth.grantTypesSupported}")
            },
        )
        then?.invoke()
    }


    /** Step 4 — `IssueService.requestAuthorization`. */
    fun requestAuthorization() = run("4 · Request authorization") {
        val session = IssuanceSession(offer, issuerConfig, authConfig)
        if (session.authConfig == null) {
            log("4 · Request authorization", "Discover the authorization server first")
            return@run
        }

        // A pre-authorized offer has no authorization leg at all: the issuer has already decided
        // to issue and handed over the code. §4.1.1 puts `issuer_state` inside the
        // authorization_code grant, so an offer without that grant has none to send — and a server
        // asked for one anyway answers "issuer state is not found". Step 5 is the next step here.
        val grants = offer?.grants
        if (grants?.authorizationCode == null && grants?.preAuthorizationCode != null) {
            log("4 · Request authorization", """
                  skipped            this offer is pre-authorized
                  grants             pre-authorized_code
                  tx_code            ${txCodeOf(offer!!)}
                  why                a pre-authorized flow has no authorization leg and no
                                     issuer_state to send — run step 5 instead
            """.trimIndent())
            return@run
        }

        val identity = walletIdentity()
        val verifier = codeVerifier
            ?: CodeVerifierService().generateCodeVerifier().also { codeVerifier = it }

        val response = IssueService().requestAuthorization(
            session = session,
            wallet = identity,
            codeVerifier = verifier,
            mode = authorizationMode,
        )

        val heading = "4 · Request authorization"
        val request = response.request

        // What actually went out. A server rejecting the request is objecting to one of these, and
        // the outcome alone does not say which.
        val sent = request?.parameters.orEmpty()
            .filterKeys { it != "client_metadata" }
            .entries
            .joinToString("\n") { (name, value) -> "      ${name.padEnd(22)} ${value.take(120)}" }

        val trace = """
              transport          ${request?.transport ?: "none"}
              endpoint           ${request?.endpoint ?: "—"}
              redirect_uri       ${request?.redirectUri ?: "—"}
              state sent         ${request?.state ?: "—"}
              wallet attestation ${if (request?.sentWalletAttestation == true) "sent" else "not sent"}
              mode               $authorizationMode
              did                ${identity.did}
              parameters sent    ${request?.parameters?.size ?: 0}
        """.trimIndent() + "\n" + sent

        when (response.outcome) {
            AuthorizationOutcome.AUTHORIZATION_CODE -> {
                authorizationCode = response.code
                log(heading, """
                    $trace
                      outcome            authorization code
                      code               ${response.code}
                      state returned     ${response.state ?: "—"}
                      state matches      ${response.state == request?.state}
                """.trimIndent())
            }

            AuthorizationOutcome.OPEN_IN_BROWSER -> log(heading, """
                $trace
                  outcome            open in browser
                  expires_in         ${response.expiresIn?.let { "$it s" } ?: "—"}
                  url                ${response.url}
            """.trimIndent())

            AuthorizationOutcome.PRESENTATION_REQUIRED -> log(heading, """
                $trace
                  outcome            presentation required (IAR, or a redirect asking for one)
                  auth_session       ${response.authSession ?: "—"}
                  expires_in         ${response.expiresIn?.let { "$it s" } ?: "—"}
                  url                ${response.url}
            """.trimIndent())

            AuthorizationOutcome.ID_TOKEN_REQUIRED -> log(heading, """
                $trace
                  outcome            id_token required
                  url                ${response.url}
            """.trimIndent())

            AuthorizationOutcome.FAILED -> log(heading, """
                $trace
                  outcome            FAILED
                  error              ${response.error?.errorCode ?: "—"}
                  description        ${response.error?.errorDescription ?: "no reason given"}
                  http status        ${response.error?.httpStatus ?: "—"}
                  raw                ${response.error?.raw?.take(200) ?: "—"}
            """.trimIndent())
        }
    }

    /**
     * Which transport the request goes through.
     *
     * Browser is what a scanned offer uses; InApp is the first-party path the wallet-provider
     * attestation bootstrap takes. Switchable here because it is the one input that changes which
     * transport runs.
     */
    var authorizationMode: AuthorizationMode = AuthorizationMode.Browser

    /** Runs the steps in sequence, stopping at the first that does not produce a result. */
    fun runAll() {
        clear()
        resolveOffer {
            discoverIssuer {
                discoverAuthServer {
                    // A pre-authorized offer skips step 4 entirely; running it anyway is what
                    // makes a server complain about a missing issuer_state.
                    if (offer?.grants?.authorizationCode == null &&
                        offer?.grants?.preAuthorizationCode != null
                    ) requestToken() else requestAuthorization()
                }
            }
        }
    }

    /**
     * Step 5 — `IssueService.processTokenRequest`.
     *
     * Takes whichever code the offer's grant provides: the pre-authorized code straight from the
     * offer, or the authorization code step 4 produced. Which one is not a toggle here — the
     * offer's grants decide it, which is the point.
     */
    fun requestToken() = run("5 · Request token") {
        val heading = "5 · Request token"
        val authServer = authConfig
        if (authServer == null) {
            log(heading, "Discover the authorization server first")
            return@run
        }

        val preAuthorized = offer?.grants?.preAuthorizationCode
        val isPreAuthorised = preAuthorized?.preAuthorizedCode != null && authorizationCode == null
        val code = if (isPreAuthorised) preAuthorized?.preAuthorizedCode else authorizationCode
        if (code.isNullOrBlank()) {
            log(heading, "No code yet — run step 4 for an authorization-code offer")
            return@run
        }

        // §6.1: a `tx_code` object in the offer means a code is required *even when the object is
        // empty*, so its presence is the test, not whether it declares a length.
        val pin = txCode.value?.takeIf { it.isNotBlank() }
        if (isPreAuthorised && preAuthorized?.transactionCode != null && pin == null) {
            log(heading, "This offer declares tx_code — enter the transaction code first")
            return@run
        }

        val identity = walletIdentity()
        val wrapped = IssueService().processTokenRequest(
            did = identity.did,
            tokenEndPoint = authServer.tokenEndpoint,
            code = code,
            codeVerifier = codeVerifier,
            isPreAuthorisedCodeFlow = isPreAuthorised,
            userPin = pin,
            version = offer?.version,
            walletUnitAttestationJWT = null,
            walletUnitProofOfPossession = null,
            redirectUri = null,
            dpopKey = identity.jwk as? ECKey,
        )

        val trace = """
              grant              ${if (isPreAuthorised) "pre-authorized_code" else "authorization_code"}
              endpoint           ${authServer.tokenEndpoint ?: "—"}
              tx_code sent       ${if (pin != null) "yes" else "no"}
              dpop               ${if (wrapped?.dpop != null) "sent" else "not sent"}
        """.trimIndent()

        val token = wrapped?.tokenResponse
        val error = wrapped?.errorResponse
        when {
            token?.accessToken != null -> log(heading, """
                $trace
                  outcome            access token
                  token_type         ${token.tokenType ?: "—"}
                  expires_in         ${token.expiresIn ?: "—"}
                  c_nonce            ${token.cNonce ?: "—"}
                  refresh_token      ${if (token.refreshToken != null) "present" else "—"}
                  auth details       ${token.authorizationDetails?.size ?: 0}
            """.trimIndent())

            token?.error != null -> log(heading, """
                $trace
                  outcome            FAILED
                  error              ${token.error}
                  description        ${token.errorDescription ?: "—"}
            """.trimIndent())

            else -> log(heading, """
                $trace
                  outcome            FAILED
                  error              ${error?.errorCode ?: "—"}
                  description        ${error?.errorDescription ?: "no reason given"}
                  http status        ${error?.httpStatus ?: "—"}
                  raw                ${error?.raw?.take(200) ?: "—"}
            """.trimIndent())
        }
    }

    /**
     * One throwaway key per scan rather than per step: steps 4 and 5 must present the same wallet,
     * since the token request's DPoP proof is bound to the key the authorization request used.
     */
    private fun walletIdentity(): WalletIdentity = wallet ?: run {
        val jwk = DIDService().createES256JWK(null)
        WalletIdentity(did = DIDService().createES256DID(jwk), jwk = jwk).also { wallet = it }
    }

    private fun run(label: String, block: suspend () -> Unit) {
        viewModelScope.launch {
            isLoading.value = true
            try {
                block()
            } catch (e: Exception) {
                // The harness must never die on a bad scan; an unexpected failure is a result too.
                log(label, "UNEXPECTED\n  ${e::class.simpleName}: ${e.message}")
            } finally {
                isLoading.value = false
            }
        }
    }

    private fun log(heading: String, body: String) {
        output.value = buildString {
            output.value?.takeIf { it.isNotBlank() }?.let { append(it).append("\n\n") }
            appendLine(heading)
            append(body)
        }
    }

    private fun specVersionOf(offer: CredentialOffer) = when (offer.version) {
        2 -> "OpenID4VCI 1.0"
        1 -> "pre-1.0 draft"
        else -> "unknown (${offer.version})"
    }

    private fun grantsOf(offer: CredentialOffer) = buildList {
        offer.grants?.authorizationCode?.let { add("authorization_code") }
        offer.grants?.preAuthorizationCode?.let { add("pre-authorized_code") }
    }.ifEmpty { listOf("none declared") }

    private fun txCodeOf(offer: CredentialOffer): String {
        val txCode = offer.grants?.preAuthorizationCode?.transactionCode ?: return "—"
        return "length=${txCode.length ?: "unspecified"} input_mode=${txCode.inputMode}"
    }

    private fun layoutOf(form: Any?, usedFallback: Boolean) = when {
        form == null -> "—"
        usedFallback -> "$form  ← non-spec fallback"
        else -> "$form  (spec form)"
    }

    private fun wellKnownOf(wellKnown: String?, usedFallback: Boolean) = when {
        wellKnown == null -> "—"
        usedFallback -> "$wellKnown  ← OpenID Connect Discovery fallback"
        else -> "$wellKnown  (the location OpenID4VCI names)"
    }

    private companion object {
        const val NOTHING_SCANNED = "Nothing scanned yet"
    }
}
