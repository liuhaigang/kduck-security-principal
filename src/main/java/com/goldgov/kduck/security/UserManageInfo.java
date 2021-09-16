package com.goldgov.kduck.security;

/**
 * 这是个覆盖适配类
 */
public interface UserManageInfo {
    /**
     * 获得用户当前管理范围
     *
     * @param accountName 用户名
     * @param token
     * @return
     */
    String getUserExtInfo(String accountName, String token);
}
