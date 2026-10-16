// GitHub Packages credentials for the private QR scanner artifact.
// Values live in github.properties, which is gitignored — never inline them here, this file is
// tracked. Falls back to GPR_USER / GPR_API_KEY so CI can supply them from secrets.
val githubProperties = java.util.Properties().apply {
    val file = File(settingsDir, "github.properties")
    if (file.exists()) file.inputStream().use { load(it) }
}

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }

        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/L3-iGrant/qr-code-scanner-android")

            credentials {
                username = githubProperties.getProperty("gpr.usr") ?: System.getenv("GPR_USER")
                password = githubProperties.getProperty("gpr.key") ?: System.getenv("GPR_API_KEY")
            }
        }
    }
}

rootProject.name = "eudi-wallet-oidc-android"
// The sample app depends on the private QR scanner artifact, so it is only part of the build when
// credentials for it are available. CI and JitPack have none and build the SDK alone.
val hasGitHubPackagesCredentials =
    (githubProperties.getProperty("gpr.key") ?: System.getenv("GPR_API_KEY")).isNullOrBlank().not()
if (hasGitHubPackagesCredentials) include(":app")
include(":eudi-wallet-oidc-android")
