plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.zeengal.litep2p.core"
    compileSdk = 36

    defaultConfig {
        minSdk = 24

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

        consumerProguardFiles("consumer-rules.pro")
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

    // Build flavors for thread mode selection. The native engine is compiled here, so
    // the SINGLE_THREAD_MODE CMake toggle lives in the library; :app mirrors the same
    // flavor dimension so variant matching works.
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
        }
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
    // The core library deliberately avoids AndroidX UI dependencies; only annotations.
    implementation(libs.androidx.annotation)

    testImplementation(libs.junit)
}