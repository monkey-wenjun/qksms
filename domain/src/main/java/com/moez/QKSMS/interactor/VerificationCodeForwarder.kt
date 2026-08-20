/*
 * Copyright (C) 2024 Health Sync
 *
 * 验证码转发接口：在短信接收流程中提取验证码并推送到用户配置的接口
 */
package com.moez.QKSMS.interactor

interface VerificationCodeForwarder {
    fun forward(address: String, body: String)
}
