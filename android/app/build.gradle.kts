plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "io.ashgate.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.ashgate.android"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a") }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    // The Go core with Xray: `gomobile bind` of ashgate-src/mobile, built in CI.
    implementation(files("libs/ashgate.aar"))
    implementation("androidx.security:security-crypto:1.0.0")
}
