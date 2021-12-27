package cn.kduck.security.principal.handler;

import cn.kduck.core.dao.DefaultDeleteArchiveHandler;
import cn.kduck.security.principal.AuthUser;
import cn.kduck.core.service.ValueBean;
import cn.kduck.security.principal.AuthUserHolder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.ObjectUtils;

/**
 * LiuHG
 */
public class SecurityDeleteArchiveHandler extends DefaultDeleteArchiveHandler {

    @Override
    protected void initValue(ValueBean valueBean) {
//        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//        AuthUser user = (AuthUser)auth.getPrincipal();
        AuthUser authUser = AuthUserHolder.getAuthUser();
        if(!ObjectUtils.isEmpty(authUser)) {
            valueBean.setValue("userName", authUser.getUsername());
        }
    }
}
