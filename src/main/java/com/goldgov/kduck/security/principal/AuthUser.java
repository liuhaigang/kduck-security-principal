package com.goldgov.kduck.security.principal;

import java.util.*;

/**
 * LiuHG
 */
public class AuthUser { //extends User {


    private final String username;
    private final Collection<String> authorities;
    private final boolean accountNonExpired;
    private final boolean accountNonLocked;
    private final boolean credentialsNonExpired;
    private final boolean enabled;

    private Date loginDate;
    private String loginIp;
    private String token;

    private Map details = new HashMap();

    public AuthUser(String username){
        this(username, Collections.emptyList());
    }

//    public AuthUser(UserDetails userDetails){
//        super(userDetails.getUsername(), "", userDetails.isEnabled(),userDetails.isAccountNonExpired(),userDetails.isCredentialsNonExpired(),userDetails.isAccountNonLocked(),userDetails.getAuthorities());
//        this.username = userDetails.getUsername();
//    }

    public AuthUser(String username, Collection<String> authorities) {
        this(username, true, true, true, true, authorities);
    }

    public AuthUser(String username, boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked, Collection<String> authorities) {
        this.username = username;
        this.enabled = enabled;
        this.accountNonExpired = accountNonExpired;
        this.credentialsNonExpired = credentialsNonExpired;
        this.accountNonLocked = accountNonLocked;
        this.authorities = Collections.unmodifiableCollection(authorities);
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

    public String getUserId() {
        return (String)details.get("userId");
    }

    public String getOrgId() {
        return (String)details.get("orgId");
    }

    public String getAuthOrgId() {
        String authOrgId = (String)details.get("authOrgId");
        if(authOrgId == null){
            authOrgId = getOrgId();
        }
        return authOrgId;
    }

    /**
     * 获取用户账号
     * @return
     * @deprecated 用getLoginName方法代替
     */
    @Deprecated
    public String getUsername() {
        return username;
    }

    public String getUserDisplayName() {
        return (String)details.get("userName");
    }

    public String getLoginName() {
        return username;
    }

    /**
     * 获取租户ID
     * @return
     */
    public String getTenantId(){
        return (String)details.get("tenantId");
    }
    public Collection<String> getAuthorities() {
        return authorities;
    }

    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
