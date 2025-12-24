// 文件路径: android/app/src/main/java/com/example/mandala/MandalaApplication.kt

package com.example.mandala

import android.app.Application
import android.util.Log

class MandalaApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        Log.d("MandalaApp", "Application Initialized")
    }
}
