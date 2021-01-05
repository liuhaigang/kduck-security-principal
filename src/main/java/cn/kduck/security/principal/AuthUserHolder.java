package cn.kduck.security.principal;

import cn.kduck.security.principal.filter.AuthenticatedUserFilter.AuthUserContext;

public final class AuthUserHolder {

    private AuthUserHolder(){}

    public static AuthUser getAuthUser() {
        return AuthUserContext.getAuthUser();
    }

}
