package cn.kduck.security.principal.filter;

import cn.kduck.security.principal.AuthUser;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface AuthUserExtractor {

    AuthUser extract(HttpServletRequest request, HttpServletResponse response) throws ServletException;
}
