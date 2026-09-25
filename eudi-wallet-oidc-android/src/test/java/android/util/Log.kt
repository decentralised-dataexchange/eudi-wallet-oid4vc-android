package android.util

/**
 * JVM unit tests only: stands in for the android.jar stub, whose methods throw, so code under
 * test can log. Test classes come first on the unit-test classpath.
 */
@Suppress("unused")
object Log {
    @JvmStatic fun d(tag: String?, msg: String?): Int = 0
    @JvmStatic fun i(tag: String?, msg: String?): Int = 0
    @JvmStatic fun w(tag: String?, msg: String?): Int = 0
    @JvmStatic fun e(tag: String?, msg: String?): Int = 0
    @JvmStatic fun e(tag: String?, msg: String?, tr: Throwable?): Int = 0
}
