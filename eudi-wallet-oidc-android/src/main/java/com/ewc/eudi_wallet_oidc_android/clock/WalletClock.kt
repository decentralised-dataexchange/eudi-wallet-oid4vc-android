package com.ewc.eudi_wallet_oidc_android.clock

import java.util.Date

/**
 * The single time source for every JWT this SDK mints.
 *
 * Wallets sign short-lived tokens — DPoP proofs, client-attestation PoPs, key-attestation PoPs,
 * credential proofs, KB-JWTs, VP tokens — whose `iat`/`nbf` are checked by a remote server against
 * *its* clock. Two machines never agree exactly, and a server with little or no forward tolerance
 * rejects anything it sees in its own future. BankID's authorization server does this: a PoP one
 * second old is refused with `INVALID_ISSUED_AT` (confirmed on device, 2026-08-20 — backdating
 * fixes it, removing the backdate reproduces the failure).
 *
 * So `iat` and `nbf` are stamped [skewBackdateMillis] in the past, while `exp` is measured from the
 * real [now] — the token's usable lifetime is unchanged, it is only declared to have started
 * slightly earlier.
 *
 * ```kotlin
 * // Application.onCreate, or a developer-settings screen
 * WalletClock.configure(skewBackdateMillis = 60_000)   // default
 * WalletClock.configure(skewBackdateMillis = 0)        // stamp exact device time
 * ```
 *
 * **This is a mitigation, not a cure.** It compensates only for the device running *ahead* of the
 * server; a device running behind is unaffected, and drift larger than the allowance starts failing
 * again. It also spends from any maximum-age budget the server enforces on `iat`, so keep it well
 * under the shortest token lifetime here (the client-attestation PoP, 6 minutes). The durable fix is
 * for the wallet to learn the server's own clock from its `Date` response header, and for servers to
 * apply the leeway RFC 7519 §4.1.4 expects of them.
 */
object WalletClock {

    /** Backdate applied to `iat`/`nbf`. 60 s absorbs ordinary drift without risking a max-age check. */
    const val DEFAULT_SKEW_BACKDATE_MILLIS = 60 * 1000L

    @Volatile
    var skewBackdateMillis: Long = DEFAULT_SKEW_BACKDATE_MILLIS
        private set

    /**
     * Sets the skew allowance. Call once at startup, or from a developer-settings screen.
     *
     * @param skewBackdateMillis how far into the past to stamp `iat`/`nbf`. Negative values are
     *   clamped to zero — post-dating a token would put it in *every* server's future.
     */
    @JvmStatic
    fun configure(skewBackdateMillis: Long) {
        this.skewBackdateMillis = skewBackdateMillis.coerceAtLeast(0L)
    }

    /** Real device time. Use for `exp`, so the allowance never shortens a token's life. */
    @JvmStatic
    fun now(): Date = Date()

    /** Device time minus the skew allowance. Use for `iat` and `nbf`. */
    @JvmStatic
    fun issuedAt(): Date = Date(System.currentTimeMillis() - skewBackdateMillis)
}
