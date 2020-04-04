package com.goldgov.kduck.security.principal.filter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface FilterInterceptor {

    boolean preHandle(HttpServletRequest request, HttpServletResponse response);

    void postHandle(HttpServletRequest request, HttpServletResponse response);
}
