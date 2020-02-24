package com.goldgov.kduck.security.principal;

import com.goldgov.kduck.security.principal.filter.AuthenticatedUserFilter.AuthUserContext;

public final class AuthUserHolder {

    private AuthUserHolder(){}

    public static AuthUser getAuthUser() {
        return AuthUserContext.getAuthUser();
    }

}
