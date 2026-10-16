# Credential offer resolution

How the SDK turns scanned data into a `CredentialOffer`, and how to extend or trim it.

This is the first function in an ongoing quality pass over the issuance path. See
[Status and next steps](#status-and-next-steps) at the end for where to pick up.

---

## Why this was rewritten

`IssueService.resolveCredentialOffer` was ~100 lines containing a four-attempt `try/catch` ladder
with four silent `catch { null }` blocks. Three problems mattered:

- **Five distinct failures collapsed into two indistinguishable return shapes** — a bare `null` or
  a `WrappedCredentialOffer(null, null)`. The wallet's handling is an `if / else if` with no
  `else`, so a malformed offer produced no error and never dismissed its progress spinner.
- **A non-spec `version` field was read off the wire** and trusted, so an issuer could claim any
  version, and a document carrying both draft and 1.0 shapes had its `credential_configuration_ids`
  silently discarded.
- **The last parse attempt accepted `{}`**, so "parsed successfully" guaranteed almost nothing and
  real validation happened far downstream, if at all.

---

## Architecture

`IssueService.resolveCredentialOffer` keeps its signature and delegates:

```kotlin
override suspend fun resolveCredentialOffer(data: String?): WrappedCredentialOffer =
    offerResolver.resolve(data)
```

```
services/issue/offer/
  CredentialOfferResolver.kt      orchestration: source -> parse -> validate
  CredentialOfferPolicy.kt        what we accept; configurable
  CredentialOfferValidator.kt     spec conformance, one place
  CredentialOfferSpecVersion.kt   V1_0 | Draft
  CredentialOfferException.kt     typed failures, each with a user-facing message
  OfferUri.kt                     query parsing on java.net (keeps the package off-device testable)
  source/
    CredentialOfferSource.kt          interface
    InlineCredentialOfferSource.kt    ?credential_offer=
    RemoteCredentialOfferSource.kt    ?credential_offer_uri=
    legacy/InitiateIssuanceOfferSource.kt
  parser/
    CredentialOfferParser.kt          interface
    OpenId4VciV1OfferParser.kt        ** primary **
    legacy/EbsiDraftOfferParser.kt
    legacy/EwcDraftOfferParser.kt
```

Two interfaces, both earned: each has several implementations that genuinely vary. Everything else
is a plain class.

### Flow

```
data ──► pick source ──► retrieve document ──► parse to JSON ──► pick parser ──► validate ──► CredentialOffer
           │                    │                                    │              │
     supports(data)      HTTP GET if remote                  supports(json)   spec rules
```

Any failure becomes a `WrappedCredentialOffer` carrying an `errorResponse`. **Never a bare null,
never an empty wrapper** — that contract is what makes the caller's error path reachable.

### Adding a transfer mechanism

Implement `CredentialOfferSource` and add it to `CredentialOfferResolver.defaultSources()`:

```kotlin
class MyOfferSource : CredentialOfferSource {
    override val name = "my_mechanism"
    override fun supports(data: String) = OfferUri.hasQueryParam(data, "my_param")
    override suspend fun retrieve(data: String, policy: CredentialOfferPolicy): String = ...
}
```

Sources are consulted in order. If more than one matches and
`CredentialOfferPolicy.rejectAmbiguousOffers` is set, the offer is rejected — the spec forbids
carrying both `credential_offer` and `credential_offer_uri`.

### Adding a spec revision

Implement `CredentialOfferParser`, declare its `specVersion`, and add it to `defaultParsers()`.
Detection must be by **document shape only**; `supports` and `parse` must be pure.

---

## Version strategy

```kotlin
enum class CredentialOfferSpecVersion(internal val legacyVersionCode: Int) {
    V1_0(2),   // OpenID4VCI 1.0: credential_configuration_ids, tx_code
    Draft(1),  // pre-1.0: credentials[], user_pin_required
}
```

`V1_0` is the target and is always tried first, so a draft parser only ever sees a document 1.0 has
declined.

`legacyVersionCode` is written to `CredentialOffer.version`. It is a **compatibility shim**: the
wallet keys `user_pin` vs `tx_code`, and first-vs-last `types` selection, off that Int, and reads
`WrappedCredentialOffer` in 49 places. The enum is the internal truth; the Int cannot change.

### Removing draft support

1. Delete `parser/legacy/` and `source/legacy/`.
2. Remove the three entries below the `--- legacy ---` comments in
   `CredentialOfferResolver.defaultSources()` and `defaultParsers()`.
3. Delete `models/v1/CredentialOfferEbsiV1.kt`, `models/v1/CredentialOfferEwcV1.kt`, and the two
   draft secondary constructors in `models/CredentialOffer.kt`.
4. Delete the `Draft` enum case and `legacyVersionCode`.

Nothing else references them. Until then, drafts can be disabled at runtime with
`CredentialOfferPolicy(allowDraftOffers = false)`.

---

## Policy

```kotlin
CredentialOfferPolicy(
    allowedUriSchemes = setOf("https", "http"),  // spec says https; http kept for local issuers
    requireJsonContentType = false,
    maxOfferBytes = 256 * 1024,
    rejectAmbiguousOffers = true,
    allowDraftOffers = true,
)
```

`CredentialOfferPolicy.Default` preserves the SDK's previous behaviour.
`CredentialOfferPolicy.Strict` is OpenID4VCI 1.0 as written: https only, JSON enforced, no drafts.

```kotlin
IssueService(offerPolicy = CredentialOfferPolicy.Strict)
```

Note this also closes `file:`, `ftp:` and `jar:`, which the previous check accepted — the URI is
fetched with no host allowlist, so that was the real exposure.

---

## Spec conformance (OpenID4VCI 1.0 §4)

| Requirement | Status |
|---|---|
| `credential_offer` / `_uri` MUST NOT both be present | enforced (policy) |
| `credential_offer_uri` MUST be https | policy; `http` allowed by default |
| Fetch MUST be GET, media type `application/json` | GET + `Accept` header; type check under `Strict` |
| Offer cannot be signed / `application/jwt` | rejected, by content type and by JWT shape |
| `credential_issuer` REQUIRED | validated, must be an absolute URL |
| `credential_configuration_ids` REQUIRED, non-empty, unique | validated |
| `pre-authorized_code` REQUIRED within its grant | validated |
| `tx_code.input_mode` default `numeric` | defaulted; unknown values fall back |
| `tx_code.description` MUST NOT exceed 300 chars | truncated |
| Empty `tx_code` object still requires a code | honoured |
| Unrecognized parameters MUST be ignored | Gson ignores unknown keys |
| **`grants` absent/empty → determine from AS metadata** | **not implemented** — see below |

`interval` is **not** part of the pre-authorized-code grant in 1.0; it was removed after the early
drafts. The `interval` the SDK reads elsewhere is the *deferred credential* interval, a different
mechanism.

### Known deferral

When `grants` is absent, the spec says the wallet MUST determine supported grant types from the
authorization server's metadata. That spans resolution *and* discovery, so it belongs to the
authorization function. Today such an offer resolves and is treated as an authorization-code flow
with no `issuer_state`.

---

## Bugs fixed

| | |
|---|---|
| **Hung spinner** | Failures now always carry an `errorResponse`, so the wallet's existing error branch fires and the spinner clears. No app change needed. |
| **Wire `version` trusted** | Version is derived from document shape; the field is ignored. |
| **Fabricated PIN length** | Draft `user_pin_required: true` produced `TxCode(length = 4)`; drafts declare no length, and the PIN screen sized its field from that 4. Now `length = null`, `TxCode` still non-null so the prompt still appears. |
| **Silent redirect** | A 302 on the offer fetch produced an error with a null description, toasting an empty string. It now has a message. |
| **Duplicate config ids** | Rejected; previously requested from the issuer twice. |
| **`{}` accepted as an offer** | No parser claims it. |

---

## Testing

63 tests, no network, all under
`src/test/java/com/ewc/eudi_wallet_oidc_android/services/issue/offer/`:

| Suite | Covers |
|---|---|
| `OfferUriTest` | query parsing, `+`-as-space, fragments, malformed escapes, scheme detection |
| `CredentialOfferParserTest` | per-revision detection and mapping; the `{}` regression |
| `CredentialOfferValidatorTest` | every spec rule, `tx_code` normalisation, draft semantics |
| `CredentialOfferResolverTest` | end to end incl. the real HTTP stack via MockWebServer |

The `credential_offer_uri` path drives the real Retrofit/OkHttp stack against `MockWebServer`,
which needs no production change because every endpoint is declared with an absolute `@Url`.

```bash
./gradlew :eudi-wallet-oidc-android:testDebugUnitTest
```

---

## Status and next steps

**Done:** offer resolution. 122 tests pass; the library and release AAR build.

**Sequence** — one function at a time, each checked against OpenID4VCI 1.0:

1. ~~`resolveCredentialOffer`~~ ✅
2. `DiscoveryService.getIssuerConfig` / `getAuthConfig`
3. `processAuthorisationRequest` — a four-branch monolith including the IAR path
4. `processTokenRequest` — **`authorization_pending` / `slow_down` are unhandled anywhere in the
   SDK** (zero occurrences), so a pre-auth issuer that defers authorization aborts the flow
5. `processCredentialRequest`
6. deferred, notification, refresh

**Pattern to repeat:** keep the `IssueService` method as a thin delegation; move the work into a
package beside it; put spec rules in one validator; make policy explicit rather than implicit;
quarantine anything draft-era under `legacy/`.

### Related work

`feature/issuance-client-facade` holds a parked one-call issuance API (`IssuanceClient`), built and
green at 310 tests, with a sample app and its own documentation. It is not merged; the intent is to
revisit it once the underlying functions have been through this pass.

Known issues recorded there: the IAR redirect shapes are misclassified by its
`RedirectResultParser`, and its result type does not yet carry the raw offer, token response or
credential response.
