package com.goldgov.kduck.security.principal;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * LiuHG
 */
public class AuthUser extends User {

    private final String userId;
    private Date loginDate;
    private String loginIp;

    private Map details = new HashMap();

    public AuthUser(String userId,String username, String password, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
        this.userId = userId;
    }

    public AuthUser(String userId,String username, String password, boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
        this.userId = userId;
    }

    public String getUserId() {
        return userId;
    }

    public Date getLoginDate() {
        return loginDate;
    }

    public String getLoginIp() {
        return loginIp;
    }

    public void setLoginIp(String loginIp) {
        if(this.loginIp != null){
            return;
        }
        this.loginIp = loginIp;
    }

    public void setAllDetailsItem(Map<String,Object> detailsItemMap) {
        details.putAll(detailsItemMap);
    }

    public void setDetailsItem(String name,Object value) {
        details.put(name,value);
    }

    public Object getDetailsItem(String name) {
        return details.get(name);
    }

    public void setLoginDate(Date loginDate) {
        this.loginDate = loginDate;
    }
}
