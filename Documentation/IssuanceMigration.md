# Issuance migration notes

What changes for a host app when it moves to the reworked OpenID4VCI issuance path (#726), and what
to do about each change.

The rework targets OpenID4VCI 1.0. Pre-1.0 drafts (EBSI, EWC) are still supported and live under
`legacy/` packages. No public method was removed: every old entry point still exists, most of them
now as deprecated wrappers over the new API. Most hosts recompile without source changes. The
sections below list what can still break, ordered by how likely a host is to hit it.

---

## Changes that need action

### Failures are no longer `null`

| API | Before | Now |
|---|---|---|
| `IssueService.resolveCredentialOffer` | `WrappedCredentialOffer?`, `null` on several failures | `WrappedCredentialOffer`, never `null`. A failure sets `errorResponse` |
| `DiscoveryService.getIssuerConfig` | `null` for a `null` or blank input; fetch failures already returned a wrapper | Always a wrapper. A failure sets `errorResponse` |
| `DiscoveryService.getAuthConfig` | Already a wrapper on every failure | Unchanged |

Only the classes were narrowed. `IssueServiceInterface` and `DiscoveryServiceInterface` still
declare the nullable return types, so a host that holds an interface-typed reference sees no
change in its signatures.

**Action:** check `errorResponse != null` rather than `== null`. A `== null` branch on the class
still compiles and never runs, so its error handling stops firing.

### Interfaces have new abstract members

Classes that implement these interfaces, including test fakes, stop compiling until the new members
are added.

| Interface | New members |
|---|---|
| `IssueServiceInterface` | `requestAuthorization`, `processAuthorisationRequestUsingIdToken`, `requestToken`, `requestCredential`, `requestDeferredCredential` |
| `NotificationServiceInterface` | `notify` |

**Action:** delegate to `IssueService` / `NotificationService`, or implement the members.

### Draft offers no longer invent a PIN length

A draft offer with `user_pin_required: true` used to produce `TxCode(length = 4)`. Drafts never
declare a length, so the field is now `null`. `TxCode` itself stays non-null, so "prompt for a
code" still works.

**Action:** do not use `txCode.length!!`. Fall back to a free-length field when it is `null`.

### Retrofit `ApiService` signatures

`fetchIssuerConfig` and `fetchAuthConfig` take two extra parameters, `accept` and `acceptLanguage`.
`fetchCredentialOffer`, `requestDeferredCredential` and `sendNotification` were added.

**Action:** only relevant if the host calls `ApiService` directly. Use `DiscoveryService` instead.

---

## Behaviour changes without a source change

| Area | Change |
|---|---|
| Offer resolution | Offers that violate 1.0 are rejected with a reason: both `credential_offer` and `credential_offer_uri`, duplicate `credential_configuration_ids`, an empty object, a signed offer, a `file:`, `ftp:` or `jar:` URI. Configurable through `IssueService(offerPolicy = ...)` |
| Offer version | Derived from the document shape. A `version` field sent by the issuer is ignored |
| Signed metadata | A signed issuer metadata document is now verified before use. A document that fails verification fails discovery rather than being decoded unchecked. Discovery asks for `application/json` only, so this applies only to an issuer that returns a JWT anyway |
| Error messages | Token and credential failures carry the issuer's `error_description` where there is one. Offer and discovery failures carry the SDK's own reason, where they used to be `null` or an empty string |
| Credential request shape | Decided by one check, `IssuanceSession.isDraftIssuer`. 1.0 is the default: `credential_configuration_id` (or `credential_identifier` when the token names one) with `proofs`. The draft body (`format` plus the revision's type field, singular `proof`) is sent only when the offer or the metadata had a draft shape, or the token carried `c_nonce` with no nonce endpoint. A 1.0 issuer without a nonce endpoint used to get the draft body; it now gets the 1.0 one. A draft issuer that returns no `c_nonce` is treated as 1.0; to step it back by hand, pass a `CredentialSubject.LegacyFormat` and `CredentialRequestPolicy.Legacy` |
| Persisted issuer metadata | `IssuerWellKnownConfiguration` gains a `version` field (1 for draft metadata, 2 for 1.0), set by the SDK and serialised by Gson. A configuration stored before this field reads back `null` and the SDK falls back to the shape of `credentials_supported` |
| Token refresh | `TokenRefreshService` reports `ErrorResponse.error = -1` on an exception, where it used to be `null` |
| `NotificationEventType` | Now a deprecated `typealias` of `services.issue.notification.NotificationEvent`. Source compatible. A host built against an older binary must be recompiled |

---

## Deprecated entry points and their replacements

The old methods keep working and will be removed in a later release. Four of them are now thin
wrappers over the new code, so a host still calling them gets the request shape, retries and
error reporting described above. The two deferred ones keep their old bodies.

| Deprecated | Replacement | Wrapper? | Deprecation warning shown on |
|---|---|---|---|
| `processAuthorisationRequest` | `requestAuthorization`, returns a typed `AuthorizationResponse` | Yes | `IssueService` only |
| `processTokenRequest` | `requestToken` with a `TokenGrant` | Yes | `IssueService` only |
| `processCredentialRequest` (fourteen parameters) | `requestCredential` with a `CredentialSubject`, returns a `CredentialOutcome` | Yes. The response carries the credentials in `credentials` only, never in the singular `credential` | Both |
| `processDeferredCredentialRequest` | `requestDeferredCredential` with `DeferredTransaction.LegacyAcceptanceToken` | **No**, old body kept | `IssueServiceInterface` only |
| `processDeferredCredentialRequestV2` | `requestDeferredCredential` with `DeferredTransaction.TransactionId` | **No**, old body kept | `IssueServiceInterface` only |
| `NotificationService.sendNotificationRequest` | `notify`, returns a `NotificationOutcome` | Yes | Both |

The sample app (`app/`) drives every step through the new API and is the reference for wiring it up.

---

## New configuration points

All of them default to behaviour that works with the issuers the SDK is used against today. The
offer, discovery, authorization, token and deferred policies have a `Strict` variant, which is
OpenID4VCI 1.0 as written and is meant for conformance testing. `CredentialRequestPolicy` and
`DeferredRequestPolicy` have a `Legacy` variant that steps the request back towards the drafts;
`CredentialRequestPolicy.Legacy` changes the proof form only.

| Policy | Passed to | Controls |
|---|---|---|
| `CredentialOfferPolicy` | `IssueService(offerPolicy = ...)` | Accepted URI schemes, JSON content type, maximum size, ambiguous offers, draft offers |
| `DiscoveryPolicy` | `DiscoveryService(policy = ...)` | Accepted schemes, well-known URL fallbacks, issuer identifier check, draft metadata, content type, `Accept-Language`, maximum size |
| `AuthorizationRequestPolicy` | `requestAuthorization(policy = ...)` | Client metadata, interactive authorization, `resource` parameter, credential scopes |
| `TokenRequestPolicy` | `requestToken(policy = ...)` | `resource` parameter, `authorization_details`, DPoP nonce retry |
| `CredentialRequestPolicy` | `requestCredential(policy = ...)` | `proofs` form, nonce retry, DPoP nonce retry |
| `DeferredRequestPolicy` | `requestDeferredCredential(policy = ...)` | `credential_identifier`, DPoP nonce retry, interval-only responses treated as pending |

See [CredentialOfferResolution.md](CredentialOfferResolution.md) for the offer side in detail.
