package com.ewc.eudi_wallet_oidc_android.services.verification.presentation

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.util.Date
import java.util.UUID

/**
 * A W3C Verifiable Presentation as a JWT (OpenID4VP 1.0 Appendix B.1): `vp.verifiableCredential`
 * holds the credentials, `aud` the client identifier, `nonce` the request's nonce, `holder` the
 * presenting DID.
 */
class JwtVpTokenBuilder {

    /** One presentation per credential, each signed with the credential's own key. */
    fun present(selected: SelectedCredential, inputs: PresentationInputs): Presentation {
        val key = selected.key ?: inputs.holder?.jwk ?: throw PresentationException.NoKey(selected.entryId)
        val did = if (selected.key != null) didOf(key) ?: inputs.holder?.did else inputs.holder?.did
        return Presentation(
            entryIds = listOf(selected.entryId),
            format = PresentationFormat.W3C_VP,
            token = sign(selected.entryId, listOf(selected.credential), key, did, inputs),
        )
    }

    /** One presentation carrying every credential, signed with the holder's key: the draft shape for several W3C VCs. */
    fun aggregate(selected: List<SelectedCredential>, inputs: PresentationInputs): Presentation {
        val entryId = selected.first().entryId
        val key = inputs.holder?.jwk ?: selected.firstNotNullOfOrNull { it.key } ?: throw PresentationException.NoKey(entryId)
        return Presentation(
            entryIds = selected.map { it.entryId },
            format = PresentationFormat.W3C_VP,
            token = sign(entryId, selected.map { it.credential }, key, inputs.holder?.did ?: didOf(key), inputs),
        )
    }

    private fun sign(entryId: String, credentials: List<String>, key: JWK, did: String?, inputs: PresentationInputs): String {
        try {
            val now = Date()
            val id = "urn:uuid:${UUID.randomUUID()}"
            val claims = JWTClaimsSet.Builder()
                .audience(inputs.request.clientId)
                .issueTime(now)
                .expirationTime(Date(now.time + EXPIRY_MS))
                .notBeforeTime(now)
                .issuer(did)
                .subject(did)
                .jwtID(id)
                .claim("nonce", inputs.request.nonce)
                .claim(
                    "vp", mapOf(
                        "@context" to listOf("https://www.w3.org/2018/credentials/v1"),
                        "holder" to did,
                        "id" to id,
                        "type" to listOf("VerifiablePresentation"),
                        "verifiableCredential" to credentials,
                    )
                )
                .build()
            val (algorithm, signer) = when (key) {
                is OctetKeyPair -> JWSAlgorithm.EdDSA to Ed25519Signer(key)
                is ECKey -> JWSAlgorithm.ES256 to ECDSASigner(key)
                else -> throw IllegalArgumentException("unsupported key type ${key.keyType}")
            }
            val header = JWSHeader.Builder(algorithm)
                .type(JOSEObjectType("JWT"))
                .keyID("$did#${did?.removePrefix("did:key:")}")
                .jwk(key.toPublicJWK())
                .build()
            return SignedJWT(header, claims).apply { sign(signer) }.serialize()
        } catch (e: PresentationException) {
            throw e
        } catch (e: Exception) {
            throw PresentationException.PresentationSigningFailed(entryId, e)
        }
    }

    /** The did:key the previous code derived for a per credential key. */
    private fun didOf(key: JWK): String? = try {
        "did:key:${key.toECKey().toPublicJWK().computeThumbprint()}"
    } catch (e: Exception) {
        null
    }

    private companion object {
        const val EXPIRY_MS = 600_000L
    }
}
