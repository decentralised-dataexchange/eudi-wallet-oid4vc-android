<h1 align="center">
    EUDI Wallet OpenID for Verifiable Credentials - Android SDK
</h1>

<p align="center">
    <a href="/../../commits/" title="Last Commit"><img src="https://img.shields.io/github/last-commit/EWC-consortium/eudi-wallet-oidc-android?style=flat"></a>
    <a href="/../../issues" title="Open Issues"><img src="https://img.shields.io/github/issues/EWC-consortium/eudi-wallet-oidc-android?style=flat"></a>
    <a href="./LICENSE" title="License"><img src="https://img.shields.io/badge/License-Apache%202.0-yellowgreen?style=flat"></a>
</p>

<p align="center">
  <a href="#about">About</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#usage">Usage</a> •
  <a href="#licensing">Licensing</a>
</p>

## About

This repository is created to align the implementation of digital wallets across the EWC LSP consortium wallet providers. This also ensures all wallets providers can self-test and sign off against the EWC Interoperability Test Bed (ITB). 

## Contributing

Feel free to improve the plugin and send us a pull request. If you find any problems, please create an issue in this repo. Wallet providers can raise a PR once they have implemented and aligned with the RFCs. 

## Usage

### Download

1. Add the JitPack repository to your build file

```kotlin
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
        maven { url 'https://jitpack.io' }
    }
}
```

2. Add the dependency

```kotlin
implementation 'com.github.decentralised-dataexchange:eudi-wallet-oidc-android:<tag>'
```

### Required Dependencies
```kotlin
 implementation("com.nimbusds:nimbus-jose-jwt:9.21")
 implementation("com.squareup.retrofit2:converter-gson:2.9.0")
```
### Functions available
#### 1. DIDService

| Function | Return Type | Description |
| -------- | -------- | ------- |
| createJWK(seed: String?) | JWK | Generate JWK of curve P-256 for an optional seed value. |
| createDID(jwk: JWK) | String | Generate a did:key:jcs-pub decentralised identifier. |

#### 2. IssueService

| Function | Return Type | Description |
| -------- | -------- | ------- |
| resolveCredentialOffer(data: String?) | CredentialOffer | To process the credential offer request |
| processAuthorisationRequest(did:String?, jwk:JWK, credential offer: CredentialOffer, codeVerifier: String, authorisationEndPoint:String) | String | This API requests to grant access to the credential endpoint. Returns URL with short lived authorisation code in query parameter |
| processTokenRequest(did:String, tokenEndPoint:String, code: String, codeVerifier:String, isPreAuthorisedCodeFlow: bool = false, userPin: String) | WrappedTokenResponse | To obtain the access token |
| processCredentialRequest(did:String, jwk:JWK, credentialIssuerUrl:String, nonce:String, credentialOffer:CredentialOffer, credentialIssuerEndPoint:String, accessToken:String) | WrappedCredentialResponse | To obtain the credential |
| processDeferredCredentialRequest(acceptanceToken:String, deferredCredentialEndPoint:String) | WrappedCredentialResponse | To obtain the credential issued in a deferred manner. |

#### 3. VerificationService

| Function | Return Type | Description |
| -------- | -------- | ------- |
| processAuthorisationRequest(data:String) | PresentationRequest | Authorisation requests can be presented to the wallet by verifying in two ways: 1) by value 2) by reference as defined in JWT-Secured Authorization Request (JAR) via use of response_uri. The custom URL scheme for authorisation requests is openid4vp://. |
| sendVPToken(did:String, jwk:JWK, presentationRequest: PresentationRequest, credentialList:List<String>) | String | Authorisation response is sent by constructing the vp_token and presentation_submission values. |
| filterCredential(credentailList:List<String>, presentationDefinition: PresentationDefinition) | List<List<String> | To filter all the credentials which is saved in the wallet. Response will be List<List<String>>. First list represents the Input descriptors and Second list will contain the credentials for each input descriptor |
| processPresentationDefinition(presentationDefinition:Any) | PresentationDefinition | To convert the presentationDefinition inside PresentationRequest to PresentationDefinition Model. |

#### 4. DiscoveryService

| Function | Return Type | Description |
| -------- | -------- | ------- |
| getIssuerConfig(credentialIssuerWellKnownURI:String?) | IssuerWellKnownConfiguration | To resolve the well-known endpoint for the credential issuer |
| getAuthConfig(authorisationServerWellKnownURI:String?) | AuthorisationServerWellKnownConfiguration | To resolve the well-known endpoint for the authorisation server |

#### 5. CodeVerifierService

| Function | Return Type | Description |
| -------- | -------- | ------- |
| generateCodeVerifier() | String | To create code verifier (https://datatracker.ietf.org/doc/html/rfc7636#section-4.1) |
| generateCodeChallenge(codeVerifier:String) | String | To generate code challenge from the code verifier (https://datatracker.ietf.org/doc/html/rfc7636#section-4.2) |

#### 6. SDJWTService

| Function | Return Type | Description |
| -------- | -------- | ------- |
| calculateSHA256Hash(inputString:String) | String | To calculate the SHA 256 hash of a string value |
| createSDJWTR(credential:String, presentationRequest:PresentationRequest, subJWK:SubJWK) | String | Creates a SD-JWT-R using the provided SD-JWT credential, presentation request, and private key. |
| processDisclosuresWithPresentationDefinition(credential:String, presentationDefinition:PresentationDefinition) | String | 
| updateIssuerJwtWithDisclosures(credential:String) | String | To update the issuer JWT with the disclosure values in right place using the "_sd" array |

### How to use in your application

#### Issuance
Refer the [Issue Verifiable Credential RFC](https://github.com/EWC-consortium/eudi-wallet-rfcs/blob/main/ewc-rfc001-issue-verifiable-credential.md) for issuance flow. 

* The credential issuance can be an authorisation flow or a pre-authorised one. 
* The credential offer can be obtained from QR code or Deeplink. Make use of `resolveCredentialOffer` for processing the credential offer
* Perform the Discovery to get the Issuer config and Autherisation server config. Use `getIssuerConfig` and `getAuthConfig` for it.
* If the credential issuance is authorisaation flow then call the `processAuthorisationRequest` and then `processTokenRequest` using the code received 
* If the credential issuance is pre-authorised, the call `processTokenRequest`, show PIN entering screen and pass the PIN in the token request if PIN required in the `Credential Offer`
* Fetch credential using the `processCredentialRequest`, in response we get the credential. If the response contains `acceptanceToken`, then poll `processDeferredCredentialRequest` unitll the credential is received.

#### Verification
Refer the [Present Verifiable Credentials RFC](https://github.com/EWC-consortium/eudi-wallet-rfcs/blob/main/ewc-rfc001-issue-verifiable-credential.md) for Verification flow.

* The presentation request can be obtained fromQR code or Deeplink. Make use of `processAuthorisationRequest` for processing the presentationRequest
* Filter the credentials save in wallet. Can make use of `filterCredential`.
* If the Presentation Request asks for SD-JWT, process the credential using the `createSDJWTR` service
* Use `sendVPToken` for verification.

## Licensing

Licensed under the Apache 2.0 License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the LICENSE for the specific language governing permissions and limitations under the License.
