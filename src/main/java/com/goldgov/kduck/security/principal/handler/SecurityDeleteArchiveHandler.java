package com.goldgov.kduck.security.principal.handler;

import com.goldgov.kduck.dao.DefaultDeleteArchiveHandler;
import com.goldgov.kduck.security.principal.AuthUser;
import com.goldgov.kduck.security.principal.AuthUserHolder;
import com.goldgov.kduck.service.ValueBean;
import org.springframework.util.ObjectUtils;

public class SecurityDeleteArchiveHandler extends DefaultDeleteArchiveHandler {
    public SecurityDeleteArchiveHandler() {
    }

    @Override
    protected void initValue(ValueBean valueBean) {
        AuthUser authUser = AuthUserHolder.getAuthUser();
        if(!ObjectUtils.isEmpty(authUser)) {
            valueBean.setValue("userName", authUser.getUsername());
        }else {
            super.getLogger().error("未能获取到用户信息。");
        }
    }
}
