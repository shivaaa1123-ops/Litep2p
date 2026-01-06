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

        ndk {
            abiFilters += "arm64-v8a"
        }

        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17"
                cppFlags += "-fexceptions"
                cppFlags += "-DHAVE_JNI"
            }
        }
    }

    buildTypes {
        debug {
            externalNativeBuild {
                cmake {
                    arguments += "-DBUILD_TESTING=ON"
                }
            }
        }
        release {
            externalNativeBuild {
                cmake {
                    arguments += "-DBUILD_TESTING=OFF"
                }
            }
        }
    }

    // Build flavors for thread mode selection
    flavorDimensions += "threadMode"
    productFlavors {
        create("multiThread") {
            dimension = "threadMode"
            // Normal multi-threaded mode (default)
            externalNativeBuild {
                cmake {
                    arguments += "-DSINGLE_THREAD_MODE=OFF"
                }
            }
        }
        create("singleThread") {
            dimension = "threadMode"
            // Single-thread mode for reduced resource usage
            externalNativeBuild {
                cmake {
                    arguments += "-DSINGLE_THREAD_MODE=ON"
                }
            }
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

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.lifecycle.livedata.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.ktx)
    implementation(libs.androidx.navigation.fragment.ktx)
    implementation(libs.androidx.navigation.ui.ktx)

    // Use libsodium from Maven Central
    implementation("com.goterl:lazysodium-java:5.1.4")
    implementation("net.java.dev.jna:jna:5.13.0")

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}