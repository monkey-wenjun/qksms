/*
 * Copyright (C) 2024 Health Sync
 *
 * 使用 Android Keystore 加密敏感配置，防止被其他应用或备份读取。
 */
package com.moez.QKSMS.repository

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal object KeystoreHelper {

    private const val KEY_ALIAS = "verification_code_forward_keystore_key"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val IV_LENGTH = 12
    private const val TAG_LENGTH = 128

    private val isSupported: Boolean
        get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M

    private fun getKey(): SecretKey {
        val keystore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return (keystore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey
                ?: generateKey()
    }

    private fun generateKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE
        )
        keyGenerator.init(
                KeyGenParameterSpec.Builder(
                        KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setRandomizedEncryptionRequired(true)
                        .build()
        )
        return keyGenerator.generateKey()
    }

    /**
     * 加密明文，返回 Base64(IV + ciphertext)。
     * 低版本设备（< API 23）不支持 Keystore 加密，直接返回明文并加上标记。
     */
    fun encrypt(plaintext: String): String {
        if (!isSupported) {
            return "PLAIN:$plaintext"
        }

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getKey())
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val combined = ByteArray(iv.size + ciphertext.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(ciphertext, 0, combined, iv.size, ciphertext.size)
        return "ENC:" + Base64.encodeToString(combined, Base64.DEFAULT)
    }

    /**
     * 解密 [encrypt] 产生的字符串。
     * 兼容旧版本明文存储和未加密迁移数据。
     */
    fun decrypt(encrypted: String): String {
        when {
            encrypted.startsWith("ENC:") -> {
                if (!isSupported) {
                    throw IllegalStateException("Keystore encrypted data cannot be decrypted on this Android version")
                }
                val combined = Base64.decode(encrypted.substring(4), Base64.DEFAULT)
                val iv = combined.copyOfRange(0, IV_LENGTH)
                val ciphertext = combined.copyOfRange(IV_LENGTH, combined.size)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, getKey(), GCMParameterSpec(TAG_LENGTH, iv))
                return String(cipher.doFinal(ciphertext), Charsets.UTF_8)
            }
            encrypted.startsWith("PLAIN:") -> return encrypted.substring(6)
            else -> {
                // 旧版本明文数据，透明迁移会在上层处理
                return encrypted
            }
        }
    }
}
