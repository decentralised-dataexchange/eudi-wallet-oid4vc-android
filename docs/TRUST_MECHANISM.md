# Trust Mechanism (OWS Trust List)

How the wallet decides whether a **verifier** (presentation) or **issuer** (issuance) is trusted,
and shows the trust chip / trust-provider detail popup. This replaced the local/static EU TSL XML
trust list with the server-backed **OWS Trust List** backend.

- **SDK repo:** `eudi-wallet-oid4vc-android` — all trust logic lives in
  `com.ewc.eudi_wallet_oidc_android.services.trust`.
- **App repo:** `data-wallet-android` — thin wrappers + UI, consumes the SDK as a local AAR.

---

## 1. Architecture

### SDK — `services/trust/`
| File | Role |
|---|---|
| `TrustMechanismInterface` | Contract: `isIssuerOrVerifierTrusted(url, x5c, trustProvidersList)` and `fetchTrustDetails(...)`. Both suspend. |
| `ServerTrustMechanismService` | **Default** impl. Server-backed, open `POST /trust-list/lookup`. Routes the identifier (x5c/kid/did) to the right body field and maps the flat response onto the TSL `TrustServiceProvider` the UI reads. |
| `TrustMechanismService` | Legacy impl. Matches against the local EU TSL **XML** trust list (cache first, then trust-list URLs). Still present, not wired into the decision path. |
| `TrustEvaluator` | Entry point used by the SDK verification filter and the app. `findTrustedX5c(jwt, jwksUri, urls, providersList)` extracts candidates (x5c → kid+jwksUri → COSE) and checks each via `isTrusted`. `trustMechanism()` is the single pick-point for the implementation. |
| `TSPServicesListDeserializer` | Gson helper for the TSL `TSPServices` shape. |

**Models** (stay in `models/`, not moved):
- `TrustList.kt` — request/response for the lookup: `TrustListLookupRequest` (x5c/kid/did/jwksUri),
  `TrustListLookupResponse` (`match`, `entry`), `TrustListEntry` (provider/service/certificateDetails).
- `TrustedRawData.kt` — the nested EU TSL structures (`TrustServiceProvider`, `TSPInformation`,
  `SchemeOperatorAddress`, `ServiceInformation`, `DigitalId`, …) the detail popup binds to.

**Network:** `services/network/ApiServices.trustListLookup(@Url url, @Body body)` (open, no auth),
built by `ApiManager`.

### App — `data-wallet-android`
| File | Role |
|---|---|
| `utils/trustServiceMechanism/TrustEvaluationService` | Thin wrapper over the SDK. Extracts the identifier, **memoizes by identifier**, calls `ServerTrustMechanismService().fetchTrustDetails(...)`. Returns a `TrustServiceProvider?` (non-null = trusted). |
| `utils/trustServiceMechanism/TrustMechanismManager` | `isIssuerOrVerifierTrusted(jwt)` (decision → `evaluate`), `trustProviderInfo(...)` (detail popup → reuses memoized `evaluate`), `getTrustDetails(x5c)`. |
| `utils/ConnectionDisplayUtils` | Verifier display name: `clientName ?: apiName ?: registryName ?: "Unknown Org"`. `apiName` reuses `evaluate` (memo). |
| `utils/trustServiceMechanism/TrustChipBinder` + `customViews/TrustChipView` + `composer/components/TrustChip` | Green trusted / red untrusted chip. |
| `fragment/NotVerifiedBottomSheet` | "Not Trusted" popup. |
| `fragment/TrustServiceProviderFragment` + `viewModels/TrustServiceProviderViewModel` | Trusted detail popup (name, address, email, service info, SKI, cert attributes). |
| `utils/trustServiceMechanism/{TrustListCache, TrustListRefreshManager}` | **Legacy** local-list cache/refresh. `refresh()` is now a no-op; retained for rollback. |

---

## 2. End-to-end flow

```
Presentation / Issuance screen
  └─ TrustMechanismManager.isIssuerOrVerifierTrusted(credentialJwt)
       └─ TrustEvaluationService.evaluate(credentialJwt)
            1. extractTrustIdentifier() → x5c leaf | kid | did   (memo key)
            2. memo hit? → return cached TrustServiceProvider?
            3. ServerTrustMechanismService().fetchTrustDetails(identifier)
                 └─ lookup(): buildLookupRequest() → {x5c|kid|did}
                      └─ POST {baseUrl}/trust-list/lookup   (open, no auth)
                      └─ response {match, entry} → mapToTrustServiceProvider(entry)
       └─ result != null → trusted
  └─ TrustChipBinder.bind(Boolean?) → green (TRUSTED) | red (UNTRUSTED_*) | hidden (null)

Tap green chip
  └─ TrustMechanismManager.trustProviderInfo(data)
       └─ TrustEvaluationService.evaluate(data)  → MEMO HIT (no second API call)
       └─ TrustServiceProviderFragment.newInstance(trustDetails, certAttrs)

SDK verification filter (OpenID4VP DCQL trusted_authorities)
  └─ FilterByTrustedAuthorities → TrustEvaluator.findTrustedX5c → isTrusted → trustMechanism()
```

**Memoization:** `TrustEvaluationService` keys its single-entry memo on the *extracted identifier*
(x5c leaf / kid / did), not the raw input. Different screens pass different forms of the same
verifier (the request JWT vs the stored `connection.x5c`), so keying on the identifier lets the chip
decision, the connection name, and the detail popup **share one lookup**.

**Fail-closed:** any failure (no identifier, network, non-2xx, malformed body) → not trusted.

---

## 3. API contract (OWS Trust List)

Base URL: `ServerTrustMechanismService.DEFAULT_BASE_URL = https://trustlist.nxd.foundation`
(override with `ServerTrustMechanismService.init(baseUrl)` for test/prod).

**`POST {baseUrl}/trust-list/lookup`** — open endpoint, `Content-Type: application/json`.
Body is exactly one identifier:
```json
{ "x5c": ["<base64 DER leaf cert>"] }   // or
{ "kid": "<key id>" }                    // or
{ "did": "did:web:…" }                   // or
{ "jwksUri": "https://…/jwks" }
```
Response:
```json
{
  "match": true,
  "entry": {
    "status": "granted",
    "provider": { "tSPName", "tSPTradeName", "streetAddress", "locality", "postalCode",
                  "countryName", "electronicAddress", "tSPInformationURI" },
    "service":  { "serviceTypeIdentifier", "serviceStatus", "statusStartingTime",
                  "serviceName", "digitalIdentity": ["<base64 cert>"] },
    "certificateDetails": [ { "subjectKeyIdentifier", "sha256Fingerprint", … } ],
    "matchedCertIndex": 0,
    "trustListSource": "nxd-tl"
  }
}
```
`entry.provider.*` → `TSPInformation`/`TSPAddress`; `entry.service.*` → `ServiceInformation`;
`certificateDetails[matchedCertIndex].subjectKeyIdentifier` → `DigitalId.x509SKI`.

---

## 4. Swapping the trust mechanism

Single pick-point in `TrustEvaluator`:
```kotlin
private fun trustMechanism(): TrustMechanismInterface = ServerTrustMechanismService()
```
- Local EU TSL XML instead: return `TrustMechanismService()`.
- Custom source: implement `TrustMechanismInterface` and return it. Both bundled impls are no-arg
  constructable, so it's a one-line change; the rest of the flow is implementation-agnostic.

---

## 5. Building / consuming the SDK in the app

The wallet consumes the SDK as a **local AAR** (not `includeBuild` — the app is on AGP 8.9.1 and the
SDK on 8.2.0, which a composite build forbids). After any SDK change:

```bash
# in eudi-wallet-oid4vc-android
./gradlew :eudi-wallet-oidc-android:assembleRelease
cp eudi-wallet-oidc-android/build/outputs/aar/eudi-wallet-oidc-android-release.aar \
   ../../L3Igrant/data-wallet-android/app/libs/eudi-wallet-oidc-android-2026.7.4.aar
```
- `app/build.gradle` picks up `app/libs/*.aar` via `fileTree`; the jitpack line is commented out.
- Keep **exactly one** `eudi-wallet-oidc-android-*.aar` in `app/libs` (two → duplicate-class build error).
- A file AAR carries no transitive deps; they are declared directly in `app/build.gradle`.

---

## 6. Evolution (what changed, in order)

1. Local EU TSL **XML** trust list → server API.
2. Integrity-gated per-lookup (Play Integrity token + nonce per call).
3. Token model: device login (`/trust-list/auth`) + refresh (`/trust-list/auth/refresh`), Bearer
   lookups, `TrustListTokenManager` — to respect Play Integrity rate limits.
4. **Open endpoint** — integrity/auth removed entirely; lookups are a plain POST. (Current.)
5. Identifier routing: x5c → + kid / did / jwksUri.
6. Response mapping: flat API `entry` → nested TSL `TrustServiceProvider` (name, address, email,
   service info, **SKI** from `certificateDetails`).
7. Memoize by extracted identifier (dedupe across chip / name / popup).
8. Consolidated all trust code into `services/trust`.
9. Documented, swappable `TrustEvaluator.trustMechanism()`.

---

## 7. Known gaps / future work (post-release)

- **Move trust-list caching into the SDK.** The local-list cache/refresh
  (`TrustListCache`, `TrustListRefreshManager`) currently lives app-side. Moving it into the SDK
  (behind/alongside `TrustMechanismService`) would make the local path self-contained, so switching
  sources is *only* changing `TrustEvaluator.trustMechanism()` — no app-side caching wiring needed.
- **Remove legacy local-trust code** in the app once the server path is proven stable:
  `TrustMechanismManager.isIssuerOrVerifierTrustedViaLocalList`, `TrustListCache`,
  `TrustListRefreshManager`, and the `resolveVerifierNameFromRegistry` fallback.
- **Production base URL** via config/`BuildConfig` (currently the constant default).
- **kid/did/jwksUri** — confirm the backend body field names against the latest Postman; `jwksUri`
  is modeled but not yet extracted from a request by the app.
- **`certificateDetails`** — only `subjectKeyIdentifier`/`sha256Fingerprint` are modeled; extend if
  the popup should surface more.
