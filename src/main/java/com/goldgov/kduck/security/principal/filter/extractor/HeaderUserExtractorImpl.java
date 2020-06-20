package com.goldgov.kduck.security.principal.filter.extractor;

import com.goldgov.kduck.security.principal.AuthUser;
import com.goldgov.kduck.security.principal.filter.AuthUserExtractor;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HeaderUserExtractorImpl implements AuthUserExtractor {

    public static final String USER_HEADER_NAME = "K-User";
    public static final String KCLOUD_USER_HEADER_NAME = "authService.LOGINID";

    @Override
    public AuthUser extract(HttpServletRequest request, HttpServletResponse response) {
        String headerUser = extractHeaderUser(request);
        if(StringUtils.hasText(headerUser)){
            return new AuthUser(headerUser);
        }
        return null;
    }

    protected String extractHeaderUser(HttpServletRequest request) {
        String userName = request.getHeader(USER_HEADER_NAME);
        if(!StringUtils.hasText(userName)){
            userName = request.getHeader(KCLOUD_USER_HEADER_NAME);;
        }
        return userName;
    }
}
