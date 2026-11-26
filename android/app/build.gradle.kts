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
        // 64-bit ARM only: nearly every phone in use runs it (32-bit-only
        // phones are left out); a second copy of the Go core for
        // armeabi-v7a doubled the APK.
        // CI also builds one with -Pashgate.abis=x86_64 for the emulator test.
        val abis = (project.findProperty("ashgate.abis") as String?)?.split(",") ?: listOf("arm64-v8a")
        ndk { abiFilters += abis }
    }
    // The Go core is stored compressed in the APK (half the download) and
    // unpacked once at install.
    packaging { jniLibs { useLegacyPackaging = true } }
    // CI signs the release with the keystore from GitHub secrets, so every
    // build has the same signature and installs over the previous one.
    val keystore = System.getenv("ANDROID_KEYSTORE_FILE")
    if (keystore != null) {
        signingConfigs.create("release") {
            storeFile = file(keystore)
            storeType = "pkcs12"
            storePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
            keyAlias = "ashgate"
            keyPassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
        }
    }
    buildTypes {
        release {
            // R8 drops unused Kotlin/AndroidX code and resources; proguard-rules.pro
            // keeps the gomobile bindings the Go core calls through JNI.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release")
        }
    }
    lint { checkReleaseBuilds = false }
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
    implementation("com.google.zxing:core:3.5.3")
    // JVM unit tests only (src/test); nothing of it goes into the APK.
    testImplementation("junit:junit:4.13.2")
}
