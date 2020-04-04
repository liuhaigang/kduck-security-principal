package com.goldgov.kduck.security.configuration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;

/**
 * 这是个覆盖适配类
 */
public interface HttpSecurityConfigurer {

    void configure(HttpSecurity http) throws Exception;

    void configure(WebSecurity web) throws Exception;
}
