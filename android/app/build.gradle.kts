import groovy.json.JsonSlurper
import java.security.MessageDigest
import java.nio.file.Files

plugins {
    id("com.android.application")
    kotlin("android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "io.github.byshadow64.tgproxy"
    compileSdk = 36
    buildToolsVersion = "35.0.0"
    testBuildType = providers.gradleProperty("tgproxy.testBuildType").getOrElse("debug")

    defaultConfig {
        applicationId = "io.github.byshadow64.tgproxy"
        minSdk = 26
        targetSdk = 36
        versionCode = 9
        versionName = "0.1.7-dev"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    buildTypes {
        getByName("release") {
            isDebuggable = false
            isMinifyEnabled = false
            vcsInfo.include = false
            // Local development delivery retains the original installed app identity.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
        // JVM OSGi metadata is duplicated by the pinned SSH jars and is unused on Android.
        resources.excludes += "META-INF/versions/**/OSGI-INF/MANIFEST.MF"
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":core"))
    implementation("androidx.core:core-ktx:1.17.0")
    implementation("androidx.activity:activity-compose:1.11.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.9.4")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation(platform("androidx.compose:compose-bom:2025.10.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation(platform("androidx.compose:compose-bom:2025.10.01"))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
}

// APK assembly must fail closed if its real SSH setup payload is missing, stale or contains extra files.
val verifyHelperPayload by tasks.registering {
    val payload = layout.projectDirectory.dir("src/main/assets/helper-payload")
    val policy = layout.projectDirectory.file("src/main/java/io/github/byshadow64/tgproxy/HelperPayloadAssets.kt")
    // An absent tree is checked below with the actionable preparation message.
    inputs.files(payload.asFileTree)
    inputs.file(policy)
    doLast {
        val marker = policy.asFile.readText().substringAfter("// BEGIN_HELPER_ALLOWLIST").substringBefore("// END_HELPER_ALLOWLIST")
        val allowed = Regex("\"([A-Za-z0-9_./-]+)\"").findAll(marker).map { it.groupValues[1] }.toSet()
        check(allowed.size == 27) { "Invalid compiled Helper allowlist" }
        val root = payload.asFile.toPath().toAbsolutePath().normalize()
        val manifest = root.resolve("manifest.json")
        check(Files.isRegularFile(manifest) && !Files.isSymbolicLink(manifest)) { "Prepare the public Helper APK assets first" }
        check(Files.size(manifest) <= 32768) { "Helper manifest exceeds bound" }
        @Suppress("UNCHECKED_CAST") val parsed = JsonSlurper().parse(manifest.toFile()) as Map<String, Any>
        check(parsed.keys == setOf("v", "files") && parsed["v"] == 1)
        @Suppress("UNCHECKED_CAST") val entries = parsed["files"] as List<Map<String, Any>>
        check(entries.size == allowed.size && entries.map { it["path"] }.toSet() == allowed)
        var total = 0L
        for (entry in entries) {
            check(entry.keys == setOf("path", "size", "sha256"))
            val path = entry["path"] as String
            val file = root.resolve(path).normalize()
            check(file.startsWith(root) && Files.isRegularFile(file) && !Files.isSymbolicLink(file))
            check(file.toRealPath().startsWith(root.toRealPath()))
            val bytes = Files.readAllBytes(file)
            check(bytes.size <= 2 * 1024 * 1024 && entry["size"] == bytes.size)
            total += bytes.size
            val hash = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }
            check(entry["sha256"] == hash) { "Helper asset hash mismatch" }
        }
        check(total <= 16 * 1024 * 1024)
        val actual = root.toFile().walkTopDown().filter { it.isFile }.map { it.relativeTo(root.toFile()).invariantSeparatorsPath }.toSet()
        check(actual == allowed + "manifest.json") { "Unexpected APK Helper file" }
    }
}
// Main APKs must verify their payload; the separate instrumentation APK carries no installer assets.
tasks.matching { it.name in setOf("mergeDebugAssets", "mergeReleaseAssets") }.configureEach { dependsOn(verifyHelperPayload) }
