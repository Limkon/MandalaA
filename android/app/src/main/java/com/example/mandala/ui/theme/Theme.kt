// 文件路徑: android/app/src/main/java/com/example/mandala/ui/theme/Theme.kt

package com.example.mandala.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

private val DarkColorScheme = darkColorScheme(
    primary = MandalaDarkPrimary,
    secondary = MandalaSecondary,
    tertiary = Pink80,
    background = MandalaDarkBackground,
    surface = MandalaDarkSurface
)

private val LightColorScheme = lightColorScheme(
    primary = MandalaPrimary,
    secondary = MandalaSecondary,
    tertiary = Pink40,
    background = MandalaBackground,
    surface = MandalaSurface,
    onPrimary = MandalaOnPrimary

    /* 其他可覆蓋的默認顏色
    onPrimary = Color.White,
    onSecondary = Color.White,
    onTertiary = Color.White,
    onBackground = Color(0xFF1C1B1F),
    onSurface = Color(0xFF1C1B1F),
    */
)

@Composable
fun MandalaTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    // Android 12+ 動態取色 (Dynamic Color)
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = colorScheme.primary.toArgb()
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = !darkTheme
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        // typography = Typography, // 如果你有自定義字體文件
        content = content
    )
}
