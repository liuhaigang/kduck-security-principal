package com.goldgov.kduck.security.principal.filter;

import com.goldgov.kduck.security.principal.AuthUser;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface AuthUserExtractor {

    AuthUser extract(HttpServletRequest request, HttpServletResponse response) throws ServletException;
}
