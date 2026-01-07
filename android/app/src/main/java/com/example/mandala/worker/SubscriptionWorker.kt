// 文件路径: android/app/src/main/java/com/example/mandala/worker/SubscriptionWorker.kt

package com.example.mandala.worker

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.example.mandala.data.NodeRepository
import com.example.mandala.utils.NodeParser
import com.example.mandala.viewmodel.UpdateInterval // [新增] 导入枚举以进行判断
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

class SubscriptionWorker(appContext: Context, workerParams: WorkerParameters) :
    CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        val repository = NodeRepository(applicationContext)
        
        // [修改] 过滤订阅列表：
        // 1. 必须是启用状态 (isEnabled)
        // 2. 更新周期不能是 "从不" (NEVER)
        // 这样可以防止 Worker 被其他订阅唤醒时，误更新了设置为手动的订阅
        val subscriptions = repository.loadSubscriptions().filter { 
            it.isEnabled && it.interval != UpdateInterval.NEVER 
        }
        
        val client = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .build()

        if (subscriptions.isEmpty()) return Result.success()

        var hasError = false
        val allCurrentNodes = repository.loadNodes().toMutableList()

        for (sub in subscriptions) {
            try {
                val request = Request.Builder()
                    .url(sub.url)
                    .header("User-Agent", "Mandala/1.1 (Android)")
                    .build()

                client.newCall(request).execute().use { response ->
                    if (response.isSuccessful) {
                        val body = response.body?.string() ?: ""
                        if (body.isNotBlank()) {
                            // 解析新节点并标记来源
                            val newNodes = NodeParser.parseList(body).map { 
                                it.copy(subscriptionUrl = sub.url) 
                            }
                            
                            // 删除该订阅旧有的节点，替换为新节点
                            allCurrentNodes.removeAll { it.subscriptionUrl == sub.url }
                            allCurrentNodes.addAll(newNodes)
                            
                            // 更新订阅的最后更新时间
                            val currentSubs = repository.loadSubscriptions().toMutableList()
                            val index = currentSubs.indexOfFirst { it.url == sub.url }
                            if (index != -1) {
                                currentSubs[index] = currentSubs[index].copy(lastUpdated = System.currentTimeMillis())
                                repository.saveSubscriptions(currentSubs)
                            }
                        }
                    } else {
                        hasError = true
                    }
                }
            } catch (e: Exception) {
                e.printStackTrace()
                hasError = true
            }
        }

        repository.saveNodes(allCurrentNodes)
        return if (hasError) Result.retry() else Result.success()
    }
}
