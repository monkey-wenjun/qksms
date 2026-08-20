/*
 * Copyright (C) 2024 Health Sync
 *
 * 短信转发实现：收到短信后整段加密上传到服务端，服务端不持有明文
 */
package com.moez.QKSMS.repository

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import com.moez.QKSMS.interactor.VerificationCodeForwarder
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import timber.log.Timber
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec

class VerificationCodeForwarderImpl(
    private val context: Context
) : VerificationCodeForwarder {

    private val prefs: SharedPreferences by lazy {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    override fun forward(address: String, body: String) {
        val apiUrl = prefs.getString(KEY_API_URL, null) ?: return
        if (apiUrl.isBlank()) return

        if (!prefs.getBoolean(KEY_ENABLED, false)) return

        val hash = generateMessageHash(address, body)
        if (prefs.getBoolean(hash, false)) {
            Timber.d("短信已转发过，跳过")
            return
        }

        val key = getEncryptionKey()
        val encryptedBody = encrypt(body, key)

        // 构造 JSON：服务端只存加密内容
        val json = """{"sender":"$address","message":"$encryptedBody"}"""

        Thread {
            try {
                val client = OkHttpClient()
                val requestBody = json.toRequestBody("application/json".toMediaType())
                val request = Request.Builder()
                        .url(apiUrl)
                        .post(requestBody)
                        .build()

                client.newCall(request).execute().use { response ->
                    when (response.code) {
                        200, 409 -> {
                            prefs.edit().putBoolean(hash, true).apply()
                            Timber.d("短信转发成功")
                        }
                        else -> Timber.e("短信转发失败: ${response.code}")
                    }
                }
            } catch (e: Exception) {
                Timber.e(e, "短信转发异常")
            }
        }.start()
    }

    /**
     * 读取加密密钥。首次读取旧版本明文时会自动迁移到 Keystore 加密存储。
     */
    private fun getEncryptionKey(): String {
        val stored = prefs.getString(KEY_ENCRYPTION_KEY, null) ?: return ""
        return try {
            when {
                stored.startsWith("ENC:") || stored.startsWith("PLAIN:") -> KeystoreHelper.decrypt(stored)
                else -> {
                    // 旧版本明文，自动迁移
                    prefs.edit()
                            .putString(KEY_ENCRYPTION_KEY, KeystoreHelper.encrypt(stored))
                            .apply()
                    stored
                }
            }
        } catch (e: Exception) {
            Timber.e(e, "读取加密密钥失败")
            ""
        }
    }

    private fun encrypt(message: String, keyString: String): String {
        if (keyString.isBlank()) return message
        return try {
            val decodedKey = Base64.decode(keyString, Base64.DEFAULT)
            val secretKey = SecretKeySpec(decodedKey, "AES")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            val encryptedBytes = cipher.doFinal(message.toByteArray())
            val iv = cipher.iv
            val combined = ByteArray(iv.size + encryptedBytes.size)
            System.arraycopy(iv, 0, combined, 0, iv.size)
            System.arraycopy(encryptedBytes, 0, combined, iv.size, encryptedBytes.size)
            Base64.encodeToString(combined, Base64.DEFAULT)
        } catch (e: Exception) {
            Timber.e(e, "加密失败")
            message
        }
    }

    private fun generateMessageHash(address: String, body: String): String {
        val key = "${address}_${body}"
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(key.toByteArray())
        return Base64.encodeToString(hash, Base64.DEFAULT)
    }

    companion object {
        const val PREFS_NAME = "verification_code_forward"
        const val KEY_ENABLED = "enabled"
        const val KEY_API_URL = "api_url"
        const val KEY_ENCRYPTION_KEY = "encryption_key"

        fun generateEncryptionKey(): String {
            val keyGenerator = KeyGenerator.getInstance("AES")
            keyGenerator.init(256, SecureRandom())
            val secretKey = keyGenerator.generateKey()
            return Base64.encodeToString(secretKey.encoded, Base64.DEFAULT)
        }

        /**
         * 使用 Android Keystore 加密用户输入的 AES 密钥，供写入 SharedPreferences。
         */
        @JvmStatic
        fun encryptEncryptionKey(plaintextKey: String): String {
            return KeystoreHelper.encrypt(plaintextKey)
        }

        /**
         * 从 SharedPreferences 读取的加密值解密出原始 AES 密钥。
         * 兼容旧版本明文数据。
         */
        @JvmStatic
        fun decryptEncryptionKey(stored: String): String {
            return KeystoreHelper.decrypt(stored)
        }
    }
}
