plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.zeengal.litep2p"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.zeengal.litep2p"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "0.2.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // Build flavors for thread mode selection. The native engine (and its
    // SINGLE_THREAD_MODE CMake toggle) now lives in :litep2p-core; these flavors
    // mirror the library's `threadMode` dimension so Gradle matches variants
    // (multiThread<->multiThread, singleThread<->singleThread).
    flavorDimensions += "threadMode"
    productFlavors {
        create("multiThread") {
            dimension = "threadMode"
            // Normal multi-threaded mode (default)
        }
        create("singleThread") {
            dimension = "threadMode"
            // Single-thread mode for reduced resource usage
            // Optional: different app suffix for testing both versions
            applicationIdSuffix = ".st"
            versionNameSuffix = "-singlethread"
        }
    }

    buildFeatures {
        viewBinding = true
        dataBinding = false
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlinOptions {
        jvmTarget = "11"
    }
}

dependencies {
    // The P2P engine: native library + public Kotlin API (Phase 2 module split).
    implementation(project(":litep2p-core"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.lifecycle.livedata.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.ktx)
    implementation(libs.androidx.navigation.fragment.ktx)
    implementation(libs.androidx.navigation.ui.ktx)
    implementation(libs.androidx.viewpager2)

    // Watchdog that restores the engine after aggressive OEM battery kills.
    implementation(libs.androidx.work.runtime.ktx)

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}