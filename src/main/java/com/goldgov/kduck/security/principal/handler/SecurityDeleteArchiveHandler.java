package com.goldgov.kduck.security.principal.handler;

import com.goldgov.kduck.dao.DefaultDeleteArchiveHandler;
import com.goldgov.kduck.security.principal.AuthUser;
import com.goldgov.kduck.service.ValueBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * LiuHG
 */
@Component
public class SecurityDeleteArchiveHandler extends DefaultDeleteArchiveHandler {

    @Override
    protected void initValue(ValueBean valueBean) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        AuthUser user = (AuthUser)auth.getPrincipal();
        valueBean.setValue("userId",user.getUserId());
        valueBean.setValue("userName",user.getUsername());
    }
}
