// Test fixture only: never shipped as part of the firewall APK.
plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }
android {
    namespace = "org.suite.firewallprobe"
    compileSdk = 35
    defaultConfig { applicationId = "org.suite.firewallprobe"; minSdk = 26; targetSdk = 35; versionCode = 1; versionName = "test-only"; testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner" }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
    lint { abortOnError = true }
}
androidComponents { beforeVariants(selector().withBuildType("release")) { it.enable = false } }

dependencyLocking { lockAllConfigurations() }

dependencies {
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    // Match the tested app graph; avoid an old prerelease annotation transitive.
    androidTestImplementation("androidx.annotation:annotation:1.8.1")
}
