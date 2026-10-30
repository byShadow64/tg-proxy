package io.github.byshadow64.tgproxy.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val LightColors = lightColorScheme(
    primary = Color(0xFF00695E),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFD1F4E9),
    onPrimaryContainer = Color(0xFF003F38),
    secondary = Color(0xFF53665F),
    secondaryContainer = Color(0xFFE0E9E3),
    onSecondaryContainer = Color(0xFF213B30),
    background = Color(0xFFF6F5F0),
    onBackground = Color(0xFF222724),
    surface = Color(0xFFFFFEFA),
    onSurface = Color(0xFF222724),
    surfaceVariant = Color(0xFFE9EDE6),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFF2F3EC),
    surfaceContainer = Color(0xFFEDEFE7),
    surfaceContainerHigh = Color(0xFFE8EBE3),
    surfaceContainerHighest = Color(0xFFE3E7DE),
    onSurfaceVariant = Color(0xFF53615B),
    outline = Color(0xFF748078),
    outlineVariant = Color(0xFFD6DDD4),
    error = Color(0xFFAD343A),
    errorContainer = Color(0xFFFFDAD9),
    onErrorContainer = Color(0xFF680D18),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF80DBC3),
    onPrimary = Color(0xFF003B31),
    primaryContainer = Color(0xFF174E42),
    onPrimaryContainer = Color(0xFFB5F5E1),
    secondary = Color(0xFFB5CDBF),
    secondaryContainer = Color(0xFF354B40),
    onSecondaryContainer = Color(0xFFD6EBDC),
    background = Color(0xFF151C1A),
    onBackground = Color(0xFFE8ECE5),
    surface = Color(0xFF1D2522),
    onSurface = Color(0xFFE8ECE5),
    surfaceVariant = Color(0xFF35443B),
    surfaceContainerLowest = Color(0xFF101613),
    surfaceContainerLow = Color(0xFF1A211D),
    surfaceContainer = Color(0xFF202923),
    surfaceContainerHigh = Color(0xFF29322B),
    surfaceContainerHighest = Color(0xFF333D35),
    onSurfaceVariant = Color(0xFFB5C4B9),
    outline = Color(0xFF87998C),
    outlineVariant = Color(0xFF3C4B41),
    error = Color(0xFFFFB3B2),
    errorContainer = Color(0xFF6C2229),
    onErrorContainer = Color(0xFFFFDAD9),
)

@Composable
fun TgProxyTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors,
        typography = Typography(),
        content = content,
    )
}
