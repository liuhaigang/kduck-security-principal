package com.goldgov.kduck.security;



import com.goldgov.kduck.service.ValueMap;

/**
 * 这是个覆盖适配类
 */
public interface UserExtInfo {

    ValueMap getUserExtInfo(String accountName);

    void setToken(String token);

    String getToken();
}
