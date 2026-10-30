package io.github.byshadow64.tgproxy.core

import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec

class SshValidationTest {
    private fun rejects(code: SshFailureCode, action: () -> Unit) {
        try { action(); fail("Expected safe rejection") } catch (failure: SshException) { assertEquals(code, failure.code); assertNull(failure.cause); assertEquals(code.name, failure.message) }
    }
    private val receipt = """{"host":"192.0.2.10","port":8444,"fingerprint":"${"ab".repeat(32)}","registry":true,"helper_id":"${RegistryCrypto.encode(ByteArray(16) { 7 })}"}"""

    @Test fun strictPublicReceiptRejectsAmbiguityTokensAndWrongEndpoint() {
        val good = SshInstallerEngine.parseResult(receipt.toByteArray(), "192.0.2.10")
        assertEquals(8444, good.port); assertEquals("ab".repeat(32), good.fingerprintHex)
        for (bad in listOf(
            receipt.replace("true", "false"), receipt.replace("true", "1"), receipt.replace("8444", "8444.0"),
            receipt.replace("8444", "08444"), receipt.replace("8444", "65536"), receipt.replace("8444", "-1"),
            receipt.replace("8444", "2147483648"), receipt.replace("8444", "\"8444\""),
            receipt.replace("\"registry\":true", "\"registry\":true,\"registry\":true"),
            receipt.dropLast(1) + ",\"token\":\"forbidden\"}", receipt + "{}", receipt.dropLast(1) + ",}",
            receipt.replace("192.0.2.10", "example.invalid"), receipt.replace("192.0.2.10", "192.0.2.11"),
            receipt.replace("ab".repeat(32), "AB".repeat(32)), receipt.replace("true", "null"),
            receipt.replace("host", "ho\\u００７３t"), receipt.replace("host", "ho\\ud800t"),
            receipt.replace(RegistryCrypto.encode(ByteArray(16) { 7 }), RegistryCrypto.encode(ByteArray(16) { 7 }) + "=="),
        )) rejects(SshFailureCode.UNVERIFIED_RESULT) { SshInstallerEngine.parseResult(bad.toByteArray(), "192.0.2.10") }
        rejects(SshFailureCode.UNVERIFIED_RESULT) { SshInstallerEngine.parseResult(byteArrayOf(0xc3.toByte(), 0x28), "192.0.2.10") }
        rejects(SshFailureCode.UNVERIFIED_RESULT) { SshInstallerEngine.parseResult(ByteArray(4097), "192.0.2.10") }
    }

    @Test fun payloadManifestCannotEscapeStageOrInjectShellAndHashesMustMatch() {
        SshInstallerEngine.validatePayload(payload())
        for (path in listOf("../deploy_helper.sh", "/root/x", "a//b", "a/./b", "a/../b", ".hidden", "a/.hidden", "a;whoami", "a\nb", "a\\b", "result.json", "payload.sha256")) {
            rejects(SshFailureCode.INVALID_PAYLOAD) { SshInstallerEngine.validatePayload(payload() + file(path, byteArrayOf(1))) }
        }
        rejects(SshFailureCode.INVALID_PAYLOAD) { SshInstallerEngine.validatePayload(payload() + payload()) }
        rejects(SshFailureCode.INVALID_PAYLOAD) { SshInstallerEngine.validatePayload(listOf(file("missing.sh", byteArrayOf(1)))) }
        rejects(SshFailureCode.INVALID_PAYLOAD) { SshInstallerEngine.validatePayload(listOf(SshPayloadFile("deploy_helper.sh", byteArrayOf(1), "00".repeat(32)))) }
        rejects(SshFailureCode.INVALID_PAYLOAD) { SshInstallerEngine.validatePayload(payload() + (1..64).map { file("x$it", byteArrayOf(1)) }) }
        rejects(SshFailureCode.INVALID_PAYLOAD) { SshInstallerEngine.validatePayload(payload() + file("large", ByteArray(4 * 1024 * 1024 + 1))) }
    }

    @Test fun numericEndpointRootOptionsAndConstantCommandRejectUnconfirmedAccess() {
        assertEquals("127.0.0.1", SshInstallerEngine.validateEndpoint(SshEndpoint("127.0.0.1")).ip)
        assertEquals("2001:db8::1", SshInstallerEngine.validateEndpoint(SshEndpoint("2001:db8:0:0::1")).ip)
        for (endpoint in listOf(SshEndpoint("localhost"), SshEndpoint("127.0.0.1", 0), SshEndpoint("127.0.0.1", 65536), SshEndpoint("127.0.0.1", 22, "root;id"), SshEndpoint("127.0.0.1", 22, "root\n"), SshEndpoint("127.0.0.1", 22, "root\r"), SshEndpoint("127.0.0.1", 22, "root\u0000"), SshEndpoint("0.0.0.0"), SshEndpoint("127.0.0.1\n"))) {
            rejects(SshFailureCode.INVALID_REQUEST) { SshInstallerEngine.validateEndpoint(endpoint) }
        }
        val options = options()
        SshInstallerEngine.validateOptions(options)
        rejects(SshFailureCode.INVALID_REQUEST) { SshInstallerEngine.validateOptions(SshInstallOptions(options.registryUrl, options.registryTrustSpki, options.publicIp)) }
        for (url in listOf("http://registry.example", "https://user:pw@registry.example", "https://registry.example/?token=x", "https://registry.example/install", "https://registry.example/#x", "https://registry.example:0")) {
            rejects(SshFailureCode.INVALID_REQUEST) { SshInstallerEngine.validateOptions(SshInstallOptions(url, options.registryTrustSpki, options.publicIp, true)) }
        }
        val stage = "/root/.tgproxy-setup-" + "12".repeat(16)
        val command = SshInstallerEngine.installerCommand(stage, options)
        assertTrue(command.startsWith("cd -- '$stage' && /usr/bin/sha256sum --check --strict --status 'payload.sha256' && /bin/bash './deploy_helper.sh' --registry-mode "))
        assertFalse(command.contains("--allow-existing-private-upgrade")); assertFalse(command.contains("sudo"))
        val upgrade = SshInstallOptions(options.registryUrl, options.registryTrustSpki, options.publicIp, true, true)
        assertTrue(SshInstallerEngine.installerCommand(stage, upgrade).endsWith(" --allow-existing-private-upgrade"))
        try { SshInstallerEngine.installerCommand("/root/x;id", options); fail() } catch (_: IllegalArgumentException) {}
    }

    @Test fun invalidRequestAlwaysClearsPasswordAndPublicObjectsHidePrivateValues() {
        val password = "synthetic-password".toCharArray()
        val endpoint = SshEndpoint("127.0.0.1")
        rejects(SshFailureCode.INVALID_REQUEST) { SshHelperInstaller.deploy(endpoint, password, SshHostKey(endpoint, "bad", byteArrayOf(1)), payload(), options().let { SshInstallOptions(it.registryUrl, it.registryTrustSpki, it.publicIp) }) }
        assertTrue(password.all { it == '\u0000' })
        assertFalse(endpoint.toString().contains(endpoint.ip)); assertFalse(options().toString().contains("registry.example"))
        val key = byteArrayOf(1, 2, 3); val preview = SshHostKey(endpoint, "test", key); key[0] = 9
        assertEquals("AQID", preview.keyBase64); assertTrue(preview.sha256Fingerprint.startsWith("SHA256:"))
    }

    companion object {
        fun file(path: String, bytes: ByteArray) = SshPayloadFile(path, bytes, MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) })
        fun payload() = listOf(file("deploy_helper.sh", "#!/bin/bash\n# synthetic public test input\n".toByteArray()), file("utils/helper.py", "# synthetic source\n".toByteArray()))
        fun options(): SshInstallOptions {
            val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            return SshInstallOptions("https://registry.example", RegistryCrypto.encode(pair.public.encoded), "192.0.2.10", true)
        }
    }
}
