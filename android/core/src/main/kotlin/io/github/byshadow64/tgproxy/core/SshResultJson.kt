package io.github.byshadow64.tgproxy.core

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction

/** Only the small, flat public installer receipt. No permissive JSON extensions. */
internal object SshResultJson {
    fun parse(bytes: ByteArray): Map<String, Any> {
        require(bytes.size in 1..4096)
        val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        return Reader(text).read()
    }

    private class Reader(private val text: String) {
        private var at = 0
        private fun whitespace() { while (at < text.length && text[at] in " \t\r\n") at++ }
        private fun take(expected: Char) { whitespace(); require(at < text.length && text[at++] == expected) }
        fun read(): Map<String, Any> {
            take('{'); val result = linkedMapOf<String, Any>(); whitespace()
            if (at < text.length && text[at] != '}') while (true) {
                require(result.size < 8); val key = string(); take(':'); whitespace()
                val value: Any = when (text.getOrNull(at)) {
                    '"' -> string()
                    't' -> literal("true", true)
                    'f' -> literal("false", false)
                    in '0'..'9' -> number()
                    else -> throw IllegalArgumentException()
                }
                require(result.put(key, value) == null); whitespace()
                if (text.getOrNull(at) != ',') break
                at++
            }
            take('}'); whitespace(); require(at == text.length); return result
        }
        private fun literal(value: String, result: Boolean): Boolean { require(text.startsWith(value, at)); at += value.length; return result }
        private fun number(): Int {
            val start = at
            while (text.getOrNull(at) in '0'..'9') at++
            val value = text.substring(start, at); require(value.length == 1 || value[0] != '0')
            return value.toInt()
        }
        private fun string(): String {
            take('"'); val result = StringBuilder()
            while (true) {
                require(at < text.length); val c = text[at++]
                when {
                    c == '"' -> return result.toString()
                    c == '\\' -> {
                        require(at < text.length)
                        result.append(when (val escaped = text[at++]) {
                            '"', '\\', '/' -> escaped
                            'b' -> '\b'; 'f' -> '\u000c'; 'n' -> '\n'; 'r' -> '\r'; 't' -> '\t'
                            'u' -> {
                                require(at + 4 <= text.length)
                                val hex = text.substring(at, at + 4); require(hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }); at += 4
                                val decoded = hex.toInt(16).toChar(); require(!decoded.isSurrogate()); decoded
                            }
                            else -> throw IllegalArgumentException()
                        })
                    }
                    else -> { require(c >= ' ' && !c.isSurrogate()); result.append(c) }
                }
                require(result.length <= 2048)
            }
        }
    }
}
