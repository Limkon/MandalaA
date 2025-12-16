Project-Root/   
├── .github/   
│   └── workflows/   
│       └── build.yml               # [CI] GitHub Actions 编译脚本 (负责串联 Go 和 Android 编译)   
│   
├── mandala-go/                     # [Core] Go 语言核心代码目录   
│   ├── go.mod                      # Go 模块定义   
│   ├── core/                       # 核心业务逻辑   
│   │   ├── config/                 # 配置解析   
│   │   ├── protocol/               # Mandala/Vless 等协议实现   
│   │   └── proxy/                  # 代理服务器与流量转发   
│   └── mobile/                     # Gomobile 接口层   
│       └── lib.go                  # 暴露给 Android 的 Start/Stop 接口   
│   
└── android/                        # [UI] Android 原生项目目录   
    ├── build.gradle.kts            # 项目级构建配置   
    ├── settings.gradle.kts         # 项目设置   
    ├── gradle.properties   
    ├── gradlew                     # Gradle Wrapper   
    │   
    └── app/                        # App 主模块   
        ├── build.gradle.kts        # 模块级构建配置 (需配置读取 libs/*.aar)   
        ├── libs/                   # [关键] CI 编译时会将生成的 mandala.aar 放入此处   
        └── src/   
            └── main/   
                ├── AndroidManifest.xml   
                ├── res/            # 资源文件 (图标, 布局, 字符串)   
                │   ├── drawable/   
                │   ├── mipmap/   
                │   └── values/   
                └── java/   
                    └── com/   
                        └── example/   
                            └── mandala/   
                                ├── MainActivity.kt         # 主入口   
                                ├── MandalaApplication.kt   # (可选) 全局 Application   
                                │   
                                ├── viewmodel/              # MVVM ViewModel   
                                │   └── MainViewModel.kt    # UI 状态管理与 Mobile 库调用   
                                │   
                                └── ui/                     # Jetpack Compose UI 组件   
                                    ├── theme/              # 主题配置 (Color, Type, Shape)   
                                    │   └── Theme.kt   
                                    ├── home/               # 首页 (大按钮)   
                                    │   └── HomeScreen.kt   
                                    ├── profiles/           # 节点列表页   
                                    │   └── ProfilesScreen.kt   
                                    └── settings/           # 设置页   
                                        └── SettingsScreen.kt   
