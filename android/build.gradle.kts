// 文件路径: android/build.gradle.kts (根项目)

// 根构建文件只定义插件版本，不应用插件 (apply false)
// 子模块 (app) 会自行应用这些插件
plugins {
    id("com.android.application") version "8.2.0" apply false
    id("org.jetbrains.kotlin.android") version "1.9.20" apply false
}

// 定义清理任务
tasks.register("clean", Delete::class) {
    delete(rootProject.buildDir)
}
