package cn.kduck.security.principal.handler;

import cn.kduck.core.dao.DefaultDeleteArchiveHandler;
import cn.kduck.security.principal.AuthUser;
import cn.kduck.core.service.ValueBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * LiuHG
 */
public class SecurityDeleteArchiveHandler extends DefaultDeleteArchiveHandler {

    @Override
    protected void initValue(ValueBean valueBean) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        AuthUser user = (AuthUser)auth.getPrincipal();
        valueBean.setValue("userName",user.getUsername());
    }
}
