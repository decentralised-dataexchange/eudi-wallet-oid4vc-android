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
                username = "xxxx"
                password = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            }
        }
    }
}

rootProject.name = "Eudi Wallet OIDC Android"
include(":app")
include(":eudi-wallet-oidc-android")
