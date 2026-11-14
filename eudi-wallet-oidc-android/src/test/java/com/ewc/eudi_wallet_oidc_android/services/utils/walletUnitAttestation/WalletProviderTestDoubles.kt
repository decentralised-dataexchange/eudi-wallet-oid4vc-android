package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation

import com.nimbusds.jose.crypto.impl.ECDSA
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/** [WalletUnitDeviceKeys] with software keys (the Android Keystore is not in JVM tests). */
internal class SoftwareDeviceKeys : WalletUnitDeviceKeys {
    private var registeredKey: DeviceKey? = null
    private var registeredAlias: String? = null
    val made = mutableListOf<DeviceKey>()
    val challenges = mutableListOf<String>()
    val discarded = mutableListOf<String>()

    /** A restore: the alias came back, the Keystore entry did not. */
    fun loseKey() {
        registeredKey = null
    }

    override val hasRegistration: Boolean get() = registeredAlias != null
    override fun registered(): DeviceKey? = registeredKey

    override fun make(challenge: String): DeviceKey {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val key = DeviceKey(
            alias = "software_${made.size}",
            signing = JcaSigningKey(pair.private, pair.public as ECPublicKey),
            x5c = listOf("leaf-${made.size}", "intermediate", "root")
        )
        made += key
        challenges += challenge
        return key
    }

    override fun markRegistered(key: DeviceKey) {
        registeredKey = key
        registeredAlias = key.alias
    }

    override fun discard(key: DeviceKey) {
        discarded += key.alias
    }

    override fun reset() {
        registeredKey = null
        registeredAlias = null
    }
}

/** A Play Integrity token that names the binding it was made for. */
internal class FakeIntegrity : WalletUnitIntegrity {
    val bindings = mutableListOf<String>()
    var failure: Exception? = null
    override suspend fun token(binding: String): String {
        failure?.let { throw it }
        bindings += binding
        return "integrity-for-$binding"
    }
}

internal fun softwareEcKey(): ECKey {
    val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    return ECKey.Builder(Curve.P_256, pair.public as ECPublicKey).privateKey(pair.private).build()
}

internal fun MockWebServer.nonce(value: String) =
    enqueue(MockResponse().setResponseCode(200).setBody("{\"nonce\":\"$value\",\"c_nonce\":\"$value\"}"))

internal fun MockWebServer.answer(status: Int, body: String) =
    enqueue(MockResponse().setResponseCode(status).setHeader("Content-Type", "application/json").setBody(body))

internal fun refusal(errorId: String, reason: String? = null): String =
    "{\"error\":\"invalid_client\",\"error_description\":\"refused\",\"error_id\":\"individual_wallet_unit.$errorId\"" +
        (reason?.let { ",\"reason\":\"$it\"" } ?: "") + "}"

/** Verifies the request signature of [request] the way the wallet provider does. */
internal fun verifiesRequestSignature(request: RecordedRequest, publicKey: ECKey): Boolean {
    val signatureInput = request.getHeader("Signature-Input") ?: return false
    val params = signatureInput.removePrefix("wp=")
    val headers = request.headers.names().associateWith { request.getHeader(it)!! }
    val base = HTTPMessageSignature.signatureBase(
        "POST", request.requestUrl.toString(), headers, WalletProviderClient.COMPONENTS, params
    ) ?: return false
    val raw = Base64.getDecoder().decode(request.getHeader("Signature")!!.removePrefix("wp=:").removeSuffix(":"))
    return Signature.getInstance("SHA256withECDSA").run {
        initVerify(publicKey.toECPublicKey())
        update(base.toByteArray(Charsets.UTF_8))
        verify(ECDSA.transcodeSignatureToDER(raw))
    }
}

internal fun verifiesDeviceSignature(request: RecordedRequest, binding: String, publicKey: ECKey): Boolean =
    Signature.getInstance("SHA256withECDSA").run {
        initVerify(publicKey.toECPublicKey())
        update(binding.toByteArray(Charsets.UTF_8))
        verify(Base64.getUrlDecoder().decode(request.getHeader("X-Wallet-Unit-Device-Signature")!!))
    }

internal fun testClient(
    server: MockWebServer,
    keys: SoftwareDeviceKeys = SoftwareDeviceKeys(),
    integrity: FakeIntegrity = FakeIntegrity()
) = WalletProviderClient(
    baseUrl = server.url("/organisation/1/service").toString(),
    appVersion = "2026.12.0",
    appBuild = "490",
    deviceModel = "samsung SM-A125F",
    deviceKeys = keys,
    integrity = integrity,
    httpClient = OkHttpClient.Builder().retryOnConnectionFailure(false).build(),
    clock = { 1794556800L }
)
