/*
 * Copyright (C) 2024 Health Sync
 *
 * 验证码转发设置界面
 */
package com.moez.QKSMS.feature.verification

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.text.InputType
import android.widget.*
import android.util.Base64
import com.moez.QKSMS.repository.VerificationCodeForwarderImpl
import java.security.SecureRandom
import javax.crypto.KeyGenerator

class VerificationCodeSettingsActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 防止截图/录屏泄露密钥与接口配置
        window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)

        val prefs = getSharedPreferences(VerificationCodeForwarderImpl.PREFS_NAME, Context.MODE_PRIVATE)

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 32, 32, 32)
        }

        val enabledSwitch = Switch(this).apply {
            text = "启用验证码转发"
            isChecked = prefs.getBoolean(VerificationCodeForwarderImpl.KEY_ENABLED, false)
        }

        val apiUrlInput = EditText(this).apply {
            hint = "HTTP 接口地址"
            setText(prefs.getString(VerificationCodeForwarderImpl.KEY_API_URL, "") ?: "")
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }

        val keyInput = EditText(this).apply {
            hint = "加密密钥（Base64，留空不加密）"
            setText(loadEncryptionKey(prefs))
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }

        val showSensitiveCheck = CheckBox(this).apply {
            text = "显示敏感信息（接口地址、密钥）"
            setOnCheckedChangeListener { _, isChecked ->
                val type = if (isChecked) {
                    InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                } else {
                    InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                }
                apiUrlInput.inputType = type
                keyInput.inputType = type
                // 光标移到最后
                apiUrlInput.setSelection(apiUrlInput.text.length)
                keyInput.setSelection(keyInput.text.length)
            }
        }

        val saveButton = Button(this).apply {
            text = "保存"
            setOnClickListener {
                val key = keyInput.text.toString().trim()
                val encryptedKey = if (key.isEmpty()) "" else try {
                    VerificationCodeForwarderImpl.encryptEncryptionKey(key)
                } catch (e: Exception) {
                    Toast.makeText(this@VerificationCodeSettingsActivity, "密钥加密失败: ${e.message}", Toast.LENGTH_LONG).show()
                    return@setOnClickListener
                }
                prefs.edit()
                        .putBoolean(VerificationCodeForwarderImpl.KEY_ENABLED, enabledSwitch.isChecked)
                        .putString(VerificationCodeForwarderImpl.KEY_API_URL, apiUrlInput.text.toString().trim())
                        .putString(VerificationCodeForwarderImpl.KEY_ENCRYPTION_KEY, encryptedKey)
                        .apply()
                Toast.makeText(this@VerificationCodeSettingsActivity, "已保存", Toast.LENGTH_SHORT).show()
                finish()
            }
        }

        val generateKeyButton = Button(this).apply {
            text = "生成并复制密钥"
            setOnClickListener {
                val newKey = generateEncryptionKey()
                keyInput.setText(newKey)
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("encryption key", newKey))
                Toast.makeText(this@VerificationCodeSettingsActivity, "密钥已生成并复制", Toast.LENGTH_SHORT).show()
            }
        }

        val helpText = TextView(this).apply {
            text = "收到包含“验证码”的短信后，会自动提取 4-6 位数字并推送到上方接口。同一验证码不会重复转发。"
            setPadding(0, 16, 0, 16)
        }

        layout.addView(enabledSwitch)
        layout.addView(TextView(this).apply { text = "接口地址" })
        layout.addView(apiUrlInput)
        layout.addView(TextView(this).apply { text = "加密密钥" })
        layout.addView(keyInput)
        layout.addView(showSensitiveCheck)
        layout.addView(generateKeyButton)
        layout.addView(saveButton)
        layout.addView(helpText)

        val scrollView = ScrollView(this)
        scrollView.addView(layout)
        setContentView(scrollView)
    }

    private fun generateEncryptionKey(): String {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(256, SecureRandom())
        val secretKey = keyGenerator.generateKey()
        return Base64.encodeToString(secretKey.encoded, Base64.DEFAULT)
    }

    private fun loadEncryptionKey(prefs: android.content.SharedPreferences): String {
        val stored = prefs.getString(VerificationCodeForwarderImpl.KEY_ENCRYPTION_KEY, null) ?: return ""
        return try {
            VerificationCodeForwarderImpl.decryptEncryptionKey(stored)
        } catch (e: Exception) {
            ""
        }
    }
}
