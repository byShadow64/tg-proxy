import java.security.MessageDigest
import groovy.json.JsonSlurper
import java.util.zip.ZipFile

plugins {
    kotlin("jvm")
}

val sshVerification by configurations.creating {
    isCanBeResolved = true
    isCanBeConsumed = false
    isTransitive = false
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation("com.github.mwiede:jsch:2.28.8") { isTransitive = false }
    runtimeOnly("org.bouncycastle:bcprov-jdk18on:1.86") { isTransitive = false }
    sshVerification("com.github.mwiede:jsch:2.28.8@jar")
    sshVerification("com.github.mwiede:jsch:2.28.8@pom")
    sshVerification("org.bouncycastle:bcprov-jdk18on:1.86@jar")
    sshVerification("org.bouncycastle:bcprov-jdk18on:1.86@pom")
    testImplementation("junit:junit:4.13.2")
    // Independent local SSH/SFTP server; none of these fixture libraries enter the APK.
    testImplementation("org.apache.sshd:sshd-common:2.20.0") { isTransitive = false }
    testImplementation("org.apache.sshd:sshd-core:2.20.0") { isTransitive = false }
    testImplementation("org.apache.sshd:sshd-sftp:2.20.0") { isTransitive = false }
    testImplementation("org.slf4j:slf4j-api:1.7.36") { isTransitive = false }
    testRuntimeOnly("org.slf4j:slf4j-nop:1.7.36") { isTransitive = false }
}

// These hashes were independently matched to Maven Central's published SHA-256 files.
// Verify the actual runtime jars too; do not weaken verification for the existing dependency graph.
val sshPins = mapOf(
    "jsch-2.28.8.jar" to "2afca1357d816028f2ac33f22407d2488a68406682973949cebb1b8ea6688a8b",
    "jsch-2.28.8.pom" to "b48f39cbc74e1e80ea7f9344e1e3b022b3f7c94fae349cfa8e2182c60ec4d7f5",
    "bcprov-jdk18on-1.86.jar" to "2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f",
    "bcprov-jdk18on-1.86.pom" to "970b70cb75a184639b6fb9ba3c465aca6a4e1a5f3fff4d65ce8574b2fd79ef38",
)
val sshLicenses = mapOf(
    "jsch-LICENSE.txt" to ("jsch-2.28.8.jar" to "META-INF/LICENSE.txt"),
    "jsch-LICENSE.JZlib.txt" to ("jsch-2.28.8.jar" to "META-INF/LICENSE.JZlib.txt"),
    "jsch-LICENSE.jBCrypt.txt" to ("jsch-2.28.8.jar" to "META-INF/LICENSE.jBCrypt.txt"),
    "bouncycastle-LICENSE.txt" to ("bcprov-jdk18on-1.86.jar" to "META-INF/LICENSE.md"),
)
val verifySshArtifacts by tasks.registering {
    inputs.files(sshVerification)
    inputs.file("ssh-artifacts.lock.json")
    inputs.files(sshLicenses.keys.map { layout.projectDirectory.file("src/main/resources/META-INF/third-party/$it") })
    doLast {
        val lock = JsonSlurper().parse(file("ssh-artifacts.lock.json")) as Map<*, *>
        val expectedDependencies = listOf(
            mapOf("group" to "com.github.mwiede", "artifact" to "jsch", "version" to "2.28.8",
                "artifacts" to sshPins.filterKeys { it.startsWith("jsch-") }),
            mapOf("group" to "org.bouncycastle", "artifact" to "bcprov-jdk18on", "version" to "1.86",
                "artifacts" to sshPins.filterKeys { it.startsWith("bcprov-") }),
        )
        check(lock.keys == setOf("v", "repository", "dependencies") && lock["v"] == 1 &&
            lock["repository"] == "https://repo.maven.apache.org/maven2/") { "Invalid SSH dependency lock" }
        val lockedDependencies = lock["dependencies"] as List<*>
        check(lockedDependencies.size == expectedDependencies.size && lockedDependencies.toSet() == expectedDependencies.toSet()) {
            "SSH dependency lock differs from the reviewed pins"
        }
        val reviewed = sshVerification.resolve().associateBy { it.name }
        check(reviewed.keys == sshPins.keys) { "Unexpected SSH dependency artifact set" }
        val runtime = configurations.getByName("runtimeClasspath").resolve().filter { it.name in sshPins }
        check(runtime.map { it.name }.toSet() == sshPins.keys.filter { it.endsWith(".jar") }.toSet()) { "Missing SSH runtime artifact" }
        for (artifact in reviewed.values + runtime) {
            val digest = MessageDigest.getInstance("SHA-256")
            artifact.inputStream().use { input ->
                val buffer = ByteArray(65536)
                while (true) { val size = input.read(buffer); if (size < 0) break; digest.update(buffer, 0, size) }
            }
            val actual = digest.digest().joinToString("") { "%02x".format(it.toInt() and 255) }
            check(actual == sshPins[artifact.name]) { "SSH dependency checksum mismatch" }
        }
        // Compare notices with the exact hash-verified jars, allowing only source-control line-ending changes.
        for ((resource, source) in sshLicenses) {
            val (jar, entry) = source
            val expected = ZipFile(reviewed.getValue(jar)).use { zip ->
                val license = checkNotNull(zip.getEntry(entry)) { "Missing upstream SSH dependency license" }
                zip.getInputStream(license).bufferedReader(Charsets.UTF_8).use { it.readText() }.replace("\r\n", "\n")
            }
            val actual = file("src/main/resources/META-INF/third-party/$resource").readText(Charsets.UTF_8).replace("\r\n", "\n")
            check(actual == expected) { "SSH dependency license differs from the reviewed artifact" }
        }
    }
}
tasks.named("compileKotlin") { dependsOn(verifySshArtifacts) }
tasks.named("jar") { dependsOn(verifySshArtifacts) }

tasks.test {
    useJUnit()
}
