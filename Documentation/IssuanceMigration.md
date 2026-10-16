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
| `DiscoveryService.getIssuerConfig` | `null` for a `null` input and some fetch failures | Always a wrapper. A failure sets `errorResponse` |
| `DiscoveryService.getAuthConfig` | `null` on some failures | Always a wrapper. A failure sets `errorResponse` |

**Action:** check `errorResponse != null` rather than `== null`. A `== null` branch still compiles
and never runs, so its error handling stops firing.

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
| Error messages | Offer, discovery, token and credential failures carry the issuer's `error_description` where there is one, instead of an empty string or a generic message |
| Token refresh | `TokenRefreshService` reports `ErrorResponse.error = -1` on an exception, where it used to be `null` |
| `NotificationEventType` | Now a deprecated `typealias` of `services.issue.notification.NotificationEvent`. Source compatible. A host built against an older binary must be recompiled |

---

## Deprecated entry points and their replacements

The old methods keep working and are implemented on top of the new ones. They will be removed in a
later release.

| Deprecated | Replacement | What the replacement adds |
|---|---|---|
| `processAuthorisationRequest` | `requestAuthorization` | A typed `AuthorizationResponse` instead of a URL with six meanings |
| `processTokenRequest` | `requestToken` with a `TokenGrant` | Invalid grant and `tx_code` combinations cannot be expressed |
| `processCredentialRequest` | `requestCredential` with a `CredentialSubject` | A `CredentialOutcome`: issued, deferred or failed |
| `processDeferredCredentialRequest` | `requestDeferredCredential` with `DeferredTransaction.LegacyAcceptanceToken` | Reports `issuance_pending` instead of `null` |
| `processDeferredCredentialRequestV2` | `requestDeferredCredential` with `DeferredTransaction.TransactionId` | Separates `issuance_pending` from `invalid_transaction_id`, returns the issuer's `interval` |
| `NotificationService.sendNotificationRequest` | `notify` | A `NotificationOutcome`, so success and refusal can be told apart |

The sample app (`app/`) drives every step through the new API and is the reference for wiring it up.

---

## New configuration points

All of them default to behaviour that works with the issuers the SDK is used against today. Where a
`Strict` variant exists it is OpenID4VCI 1.0 as written and is meant for conformance testing.
`CredentialRequestPolicy.Legacy` steps back to the draft request shape instead.

| Policy | Passed to | Controls |
|---|---|---|
| `CredentialOfferPolicy` | `IssueService(offerPolicy = ...)` | Accepted URI schemes, JSON content type, maximum size, ambiguous offers, draft offers |
| `DiscoveryPolicy` | `DiscoveryService(policy = ...)` | Accepted schemes, well-known URL fallbacks, issuer identifier check, draft metadata, content type, `Accept-Language`, maximum size |
| `AuthorizationRequestPolicy` | `requestAuthorization(policy = ...)` | Client metadata, interactive authorization, `resource` parameter, credential scopes |
| `TokenRequestPolicy` | `requestToken(policy = ...)` | `resource` parameter, `authorization_details`, DPoP nonce retry |
| `CredentialRequestPolicy` | `requestCredential(policy = ...)` | `proofs` form, nonce retry, DPoP nonce retry |
| `DeferredRequestPolicy` | `requestDeferredCredential(policy = ...)` | `credential_identifier`, DPoP nonce retry, interval-only responses treated as pending |

See [CredentialOfferResolution.md](CredentialOfferResolution.md) for the offer side in detail.
