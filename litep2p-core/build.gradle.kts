plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.dokka)
    `maven-publish`
}

// Single source of truth for the release version (see gradle.properties).
val litep2pVersion: String =
    providers.gradleProperty("LITEP2P_VERSION").get()

android {
    namespace = "com.zeengal.litep2p.core"
    compileSdk = 36

    defaultConfig {
        minSdk = 24

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // Package the standard production ABI set. Prebuilt libsodium exists
        // for each (see cpp/libsodium/<abi>/); the engine has no arch-specific
        // code. `x86` (32-bit) is excluded: its vendored libsodium.a is not
        // -fPIC and cannot be linked into a shared .so; x86_64 covers all
        // modern emulators. Reducing the list shrinks the AAR.
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }

        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17"
                cppFlags += "-fexceptions"
                cppFlags += "-DHAVE_JNI"
                // Feed the single version source into the native build so
                // litep2p_version_string() matches the POM version.
                arguments += "-DLITEP2P_VERSION=${litep2pVersion}"
            }
        }

        consumerProguardFiles("consumer-rules.pro")

        // Expose the SDK version to the Kotlin API (LiteP2P.version).
        buildConfigField("String", "LITEP2P_VERSION", "\"${litep2pVersion}\"")
    }

    // Pinned NDK for reproducible builds (matches the version CI installs).
    ndkVersion = "26.1.10909125"

    buildFeatures {
        buildConfig = true
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

    // Phase 8 lifecycle bridge: the engine's central scheduler maps deferred
    // work onto WorkManager (the only mechanism that survives process death
    // and Doze batching on Android). Runtime-only; not part of the public API.
    implementation(libs.androidx.work.runtime.ktx)

    // Used by the SDK runtime (LiteP2PService / LiteP2PRuntime / EnvironmentHints)
    // for NotificationCompat / ContextCompat / ServiceCompat, and exposed in
    // LiteP2PRuntime's public API (notificationCustomizer receives a
    // NotificationCompat.Builder), hence `api`.
    api(libs.androidx.core.ktx)

    // Exposed in the public API (Flow / StateFlow / suspend helpers), so it is
    // declared with `api` to propagate transitively to consumers.
    api(libs.kotlinx.coroutines.core)

    testImplementation(libs.junit)
}

/* ------------------------------------------------------------------ */
/* Publication (Maven Local first; same block publishes to Central)    */
/* ------------------------------------------------------------------ */

// KDoc jar — packages the Dokka HTML output as the "javadoc" artifact. (The
// sources jar is published by the AGP component automatically.)
val dokkaJar by tasks.registering(Jar::class) {
    archiveClassifier.set("javadoc")
    dependsOn(tasks.named("dokkaHtml"))
    from(layout.buildDirectory.dir("dokka/html"))
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}

// AGP registers a MavenPublication per release variant (multiThreadRelease,
// singleThreadRelease). The multiThread variant is the canonical artifact;
// singleThread is published under a distinct artifact id.
androidComponents {
    onVariants(selector().withBuildType("release")) { variant ->
        publishing {
            publications {
                register<MavenPublication>(variant.name) {
                    groupId = "com.zeengal"
                    artifactId = if (variant.flavorName == "singleThread") {
                        "litep2p-core-singleThread"
                    } else {
                        "litep2p-core"
                    }
                    version = litep2pVersion

                    afterEvaluate {
                        from(components.findByName(variant.name))
                    }
                    // The AGP component already publishes the sources jar; only
                    // the KDoc jar is added explicitly.
                    artifact(dokkaJar)

                    pom {
                        name.set("LiteP2P Core")
                        description.set("LiteP2P peer-to-peer networking SDK — native engine + Kotlin API for Android")
                        url.set("https://github.com/zeengal/Litep2p")
                        licenses {
                            license {
                                name.set("Apache License 2.0")
                                url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                                distribution.set("repo")
                            }
                        }
                        developers {
                            developer {
                                id.set("zeengal")
                                name.set("Zeengal")
                            }
                        }
                        scm {
                            connection.set("scm:git:https://github.com/zeengal/Litep2p.git")
                            developerConnection.set("scm:git:ssh://git@github.com/zeengal/Litep2p.git")
                            url.set("https://github.com/zeengal/Litep2p")
                        }
                    }
                }
            }
        }
    }
}

// Repository targets for the publications above.
publishing {
    repositories {
        // Maven Local — immediate consumable milestone with zero external
        // accounts. For Maven Central, replace/extend with mavenCentral()
        // (requires signing credentials; see docs/api-spec.md §2.1 Option C).
        mavenLocal()
    }
}