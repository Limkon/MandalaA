// 文件路径: android/app/build.gradle.kts

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.example.mandala"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.example.mandala"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
    buildFeatures {
        compose = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.4"
    }
    
    // NDK Strip 配置 (保持这个，防止 NDK 错误)
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
        jniLibs {
            useLegacyPackaging = true
            keepDebugSymbols += setOf(
                "*/armeabi-v7a/*.so",
                "*/arm64-v8a/*.so",
                "*/x86/*.so",
                "*/x86_64/*.so"
            )
        }
    }
}

dependencies {
    // 自动加载 libs 目录下的 mandala.aar
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.aar"))))

    // [关键修复] 添加 Gson 依赖
    implementation("com.google.code.gson:gson:2.10.1")

    // Android 核心库
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.6.2")
    implementation("androidx.activity:activity-compose:1.8.1")
    
    // Google Material 库
    implementation("com.google.android.material:material:1.11.0")

    // Compose UI 库
    implementation(platform("androidx.compose:compose-bom:2023.08.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
  
    // 扩展图标库
    implementation("androidx.compose.material:material-icons-extended")
    
    // Navigation 导航组件
    implementation("androidx.navigation:navigation-compose:2.7.5")
    
    // ViewModel
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.6.2")
}
