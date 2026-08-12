package com.ewc.eudi_wallet_oidc_android.logging

import android.util.Log
import okhttp3.logging.HttpLoggingInterceptor

/**
 * Logging for the SDK. **Silent until the host turns it on.**
 *
 * Everything this SDK handles is confidential — issued credentials, access and refresh tokens, DPoP
 * proofs, wallet attestations, PID attributes. Anything written to logcat is readable by any app
 * holding `READ_LOGS`, by adb, and by some device log collectors, so a library has no business
 * logging by default.
 *
 * The shape follows what OkHttp's `HttpLoggingInterceptor`, Coil and Ktor do: a level, a sink the
 * host supplies, and off unless asked. A host that already has a logging stack (Timber, Crashlytics,
 * a file) implements [Sink] and everything routes there instead of logcat.
 *
 * ```kotlin
 * // Application.onCreate — debug builds only
 * Logger.configure(
 *     level = Logger.Level.DEBUG,
 *     networkLevel = Logger.NetworkLevel.BODY,
 * )
 *
 * // or route into the host's own logger
 * Logger.configure(
 *     level = Logger.Level.DEBUG,
 *     sink = Logger.Sink { priority, tag, message, t -> Timber.log(priority, t, message) },
 * )
 * ```
 *
 * Deliberately **not** driven by the SDK's own `BuildConfig.DEBUG`: in a published AAR that is
 * always `false` regardless of how the host was built, so it would disable logging for everyone.
 */
object Logger {

    /** Severity gate for the SDK's own messages. [NONE] disables them entirely. */
    enum class Level(internal val priority: Int) {
        NONE(Int.MAX_VALUE),
        ERROR(Log.ERROR),
        WARN(Log.WARN),
        INFO(Log.INFO),
        DEBUG(Log.DEBUG),
        VERBOSE(Log.VERBOSE),
    }

    /** How much of each HTTP call is logged. Mirrors `HttpLoggingInterceptor.Level`. */
    enum class NetworkLevel {
        /** No network logging. */
        NONE,

        /** Method, URL, status, size. */
        BASIC,

        /** BASIC plus headers, with the sensitive ones redacted. */
        HEADERS,

        /**
         * HEADERS plus full bodies. Buffers each response into memory and copies it to a String, so
         * expect roughly twice the payload in transient heap per call — issuer metadata alone can
         * be hundreds of KB. Debug builds only.
         */
        BODY,
    }

    /** Where log lines go. Implement to route into the host's own logging stack. */
    fun interface Sink {
        fun log(priority: Int, tag: String, message: String, throwable: Throwable?)
    }

    /** Default sink — plain `android.util.Log`. */
    @JvmField
    val AndroidLogSink = Sink { priority, tag, message, throwable ->
        if (throwable != null) Log.println(priority, tag, "$message\n${Log.getStackTraceString(throwable)}")
        else Log.println(priority, tag, message)
    }

    @Volatile
    var level: Level = Level.NONE
        private set

    @Volatile
    var networkLevel: NetworkLevel = NetworkLevel.NONE
        private set

    @Volatile
    private var sink: Sink = AndroidLogSink

    /**
     * The interceptor `ApiManager` installs. Owned here so [configure] applies whether it is called
     * before or after the HTTP client is first built. Sensitive headers are redacted even at
     * [NetworkLevel.BODY] — the body may still carry secrets, which is why BODY is debug-only.
     */
    @JvmStatic
    val networkInterceptor: HttpLoggingInterceptor =
        HttpLoggingInterceptor(object : HttpLoggingInterceptor.Logger {
            override fun log(message: String) {
                // Routed through the host's sink rather than straight to logcat, so network lines
                // land wherever the SDK's own messages do.
                sink.log(Log.DEBUG, "SdkNetwork", message, null)
            }
        }).apply {
            setLevel(HttpLoggingInterceptor.Level.NONE)
            redactHeader("Authorization")
            redactHeader("DPoP")
            redactHeader("Cookie")
            redactHeader("Set-Cookie")
        }

    /**
     * Turns logging on. Call once at startup, from a debug path only.
     *
     * @param level severity gate for the SDK's own messages.
     * @param networkLevel how much of each HTTP call to log.
     * @param sink where lines go; defaults to logcat.
     */
    @JvmStatic
    @JvmOverloads
    fun configure(
        level: Level = Level.NONE,
        networkLevel: NetworkLevel = NetworkLevel.NONE,
        sink: Sink = AndroidLogSink,
    ) {
        this.level = level
        this.sink = sink
        this.networkLevel = networkLevel
        networkInterceptor.setLevel(
            when (networkLevel) {
                NetworkLevel.NONE -> HttpLoggingInterceptor.Level.NONE
                NetworkLevel.BASIC -> HttpLoggingInterceptor.Level.BASIC
                NetworkLevel.HEADERS -> HttpLoggingInterceptor.Level.HEADERS
                NetworkLevel.BODY -> HttpLoggingInterceptor.Level.BODY
            }
        )
    }

    /** Convenience for the common case: everything on, or everything off. */
    @JvmStatic
    fun setEnabled(enabled: Boolean) {
        if (enabled) configure(Level.DEBUG, NetworkLevel.BODY) else configure()
    }

    // MARK: - Internal call sites -----------------------------------------

    @JvmStatic
    fun v(tag: String, message: String, throwable: Throwable? = null) =
        log(Log.VERBOSE, tag, message, throwable)

    @JvmStatic
    fun d(tag: String, message: String, throwable: Throwable? = null) =
        log(Log.DEBUG, tag, message, throwable)

    @JvmStatic
    fun i(tag: String, message: String, throwable: Throwable? = null) =
        log(Log.INFO, tag, message, throwable)

    @JvmStatic
    fun w(tag: String, message: String, throwable: Throwable? = null) =
        log(Log.WARN, tag, message, throwable)

    @JvmStatic
    fun e(tag: String, message: String, throwable: Throwable? = null) =
        log(Log.ERROR, tag, message, throwable)

    private fun log(priority: Int, tag: String, message: String, throwable: Throwable?) {
        val gate = level
        if (gate == Level.NONE || priority < gate.priority) return
        sink.log(priority, tag, message, throwable)
    }
}
