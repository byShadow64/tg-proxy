package io.github.byshadow64.tgproxy

import android.content.res.AssetManager
import android.util.JsonReader
import android.util.JsonToken
import io.github.byshadow64.tgproxy.core.SshPayloadFile
import java.security.MessageDigest

/** Only the exact public source allowlist, checked by build and runtime, enters an SSH upload. */
object HelperPayloadAssets {
    private const val ROOT = "helper-payload/"
    private const val TOTAL_LIMIT = 16 * 1024 * 1024
    // BEGIN_HELPER_ALLOWLIST
    val ALLOWED_PATHS = setOf(
        "helper_server.py", "helper_pairing.py", "deploy_helper.sh", "tg-helper.service", "LICENSE",
        "proxy/__init__.py", "proxy/config.py", "proxy/balancer.py", "proxy/utils.py", "proxy/http_transport.py", "proxy/project.py",
        "helper_registry.py", "helper_registry_agent.py", "helper_enrollment.py", "deploy_helper_registry.sh",
        "proxy/registry_protocol.py", "proxy/registry_helper.py", "proxy/route_policy.py",
        "helper_requirements.txt", "helper_registry_requirements.txt", "helper_certbot_requirements.txt",
        "tg-helper-registry-agent.service", "tg-helper-registry-agent.timer", "tg-helper-enroll.service",
        "tg-helper-certbot-renew.service", "tg-helper-certbot-renew.timer", "helper_registry_renew.sh",
    )
    // END_HELPER_ALLOWLIST
    private class Entry(val path: String, val size: Int, val sha256: String)
    fun load(assets: AssetManager): List<SshPayloadFile> {
        val bytes = assets.open(ROOT + "manifest.json").use { it.readBytesBounded(32 * 1024) }
        val entries = parseManifest(bytes)
        var total = 0
        return entries.map { entry ->
            total += entry.size; require(total <= TOTAL_LIMIT)
            val content = assets.open(ROOT + entry.path).use { it.readBytesBounded(entry.size) }
            require(content.size == entry.size)
            val actual = MessageDigest.getInstance("SHA-256").digest(content).joinToString("") { "%02x".format(it.toInt() and 255) }
            require(actual == entry.sha256)
            SshPayloadFile(entry.path, content, entry.sha256)
        }
    }
    private fun parseManifest(bytes: ByteArray): List<Entry> {
        require(bytes.isNotEmpty())
        val decoder = Charsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT).onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
        return JsonReader(java.io.InputStreamReader(bytes.inputStream(), decoder)).use { json ->
            json.isLenient = false
            fun string(): String { require(json.peek() == JsonToken.STRING); return json.nextString() }
            fun number(): Int { require(json.peek() == JsonToken.NUMBER); val value = json.nextString(); require(value.matches(Regex("0|[1-9][0-9]*"))); return value.toInt() }
            val top = mutableSetOf<String>(); val entries = mutableListOf<Entry>(); val seen = mutableSetOf<String>()
            json.beginObject()
            while (json.hasNext()) {
                val name = json.nextName(); require(top.add(name))
                when (name) {
                    "v" -> require(number() == 1)
                    "files" -> {
                        json.beginArray()
                        while (json.hasNext()) {
                            require(entries.size < ALLOWED_PATHS.size)
                            json.beginObject(); val keys = mutableSetOf<String>(); var path: String? = null; var size: Int? = null; var sha: String? = null
                            while (json.hasNext()) {
                                val key = json.nextName(); require(keys.add(key))
                                when (key) { "path" -> path = string(); "size" -> size = number(); "sha256" -> sha = string(); else -> error("INVALID_PUBLIC_PAYLOAD") }
                            }
                            json.endObject()
                            require(keys == setOf("path", "size", "sha256"))
                            val file = path!!; val length = size!!; val digest = sha!!
                            require(file in ALLOWED_PATHS && seen.add(file) && length in 0..2 * 1024 * 1024 && digest.matches(Regex("[0-9a-f]{64}")))
                            entries.add(Entry(file, length, digest))
                        }
                        json.endArray()
                    }
                    else -> error("INVALID_PUBLIC_PAYLOAD")
                }
            }
            json.endObject(); require(top == setOf("v", "files") && seen == ALLOWED_PATHS && json.peek() == JsonToken.END_DOCUMENT)
            entries
        }
    }
    private fun java.io.InputStream.readBytesBounded(maximum: Int): ByteArray {
        val output = java.io.ByteArrayOutputStream(); val buffer = ByteArray(8192)
        while (true) { val count = read(buffer); if (count < 0) break; require(output.size() + count <= maximum); output.write(buffer, 0, count) }
        return output.toByteArray()
    }
}
