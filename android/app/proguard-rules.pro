# 文件路径: android/app/proguard-rules.pro

# 保护数据模型类，防止 Gson 解析失败
-keep class com.example.mandala.viewmodel.Node { *; }
-keep class com.example.mandala.viewmodel.Subscription { *; }
-keep class com.example.mandala.viewmodel.UpdateInterval { *; }
-keep class com.example.mandala.viewmodel.AppStrings { *; }

# 保持 Gson 的相关注解
-keepattributes Signature
-keepattributes *Annotation*
-dontwarn com.google.gson.**
