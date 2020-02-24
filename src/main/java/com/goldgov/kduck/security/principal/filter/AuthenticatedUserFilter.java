package com.goldgov.kduck.security.principal.filter;

import com.goldgov.kduck.cache.CacheHelper;
import com.goldgov.kduck.security.UserExtInfo;
import com.goldgov.kduck.security.principal.AuthUser;
import com.goldgov.kduck.security.principal.KduckSecurityPrincipalProperties;
import com.goldgov.kduck.service.ValueMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

public class AuthenticatedUserFilter extends GenericFilterBean {

    @Autowired
    private KduckSecurityPrincipalProperties securityProperties;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired(required = false)
    private UserExtInfo userExtInfo;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String accessToken = extractToken(httpRequest);
        if(accessToken != null){
            //TODO 先判断缓存有没有
            //TODO 根据token调用认证服务的user_info接口得到认证用户并缓存，如果得到返回错误信息，比如token过期或无效，需要同时清除对应缓存
            //TODO 如果没配置客户端user_info链接，默认执行本地请求或使用TokenStore？
            //TODO 创建登录成功事件，设置登录时间、IP以及清除登录失败记录

            if (org.springframework.util.StringUtils.hasText(securityProperties.getUserInfoUri())){
//                throw new IllegalArgumentException("Oauth2调用获取用户接口失败，缺少kduck.security.oauth2.client.provider.userInfoUri配置");
                String userInfoUri =securityProperties.getUserInfoUri();
                URI uri;
                try {
                    uri = new URI(userInfoUri);
                } catch (URISyntaxException e) {
                    throw new ServletException("user_info的链接格式不合法：" + userInfoUri,e);
                }

                if(!httpRequest.getRequestURI().equals(uri.getPath())){

                    ResponseEntity<AuthUserProxy> authUserEntity;
                     String userInfoUrl = userInfoUri + "?" + OAuth2AccessToken.ACCESS_TOKEN + "=" + accessToken;
                    try{
                        authUserEntity = restTemplate.getForEntity(userInfoUrl, AuthUserProxy.class);
                    }catch(HttpClientErrorException e){
                        throw new ServletException("调用用户信息接口返回客户端错误（4xx）：CODE=" + e.getRawStatusCode() + "，URL=" + userInfoUrl,e);
                    }catch(HttpServerErrorException e){
                        throw new ServletException("调用用户信息接口返回服务端错误（5xx）：CODE=" + e.getRawStatusCode() + "，URL=" + userInfoUrl,e);
                    }

                    AuthUserProxy userInfo = authUserEntity.getBody();
                    if(userInfo != null){
                        List<String> authorities = userInfo.getAuthorities();
                        List<GrantedAuthority> authoritiesSet = new ArrayList<>(authorities.size());
                        if(authorities != null){
                            for (String authority : authorities) {
                                authoritiesSet.add(new SimpleGrantedAuthority(authority));
                            }
                        }
                        AuthUser authUser = new AuthUser(userInfo.getUserId(),userInfo.getUsername(),"",authoritiesSet);
                        authUser.eraseCredentials();
                        authUser.setAllDetailsItem(userInfo.getDetails());
                        AuthUserContext.setAuthUser(authUser);
                        CacheHelper.put(accessToken,authUser,3600);
                    }
                }

            } else {
                throw new RuntimeException("未配置OAuth2的用户信息接口kduck.security.oauth2.client.provider.userInfoUri");
            }
        }else{
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if(authentication instanceof UsernamePasswordAuthenticationToken){
                Object principal = authentication.getPrincipal();
                if(principal instanceof AuthUser){
                    AuthUser authUser = (AuthUser)principal;
                    if(userExtInfo != null) {
                        ValueMap userExtInfo = this.userExtInfo.getUserExtInfo(authUser.getUsername());
                        authUser.setAllDetailsItem(userExtInfo);
                    }
                    AuthUserContext.setAuthUser(authUser);
                }
//                    else{
//                        throw new IllegalArgumentException("无法识别的认证对象：" + principal);
//                    }
            }

        }

        try{
            chain.doFilter(request,response);
        }finally {
            AuthUserContext.reset();
        }

    }

    @Override
    public void destroy() {
        AuthUserContext.reset();
    }

    protected String extractToken(HttpServletRequest request) {
        String token = extractHeaderToken(request);
        if (token == null) {
            token = request.getParameter(OAuth2AccessToken.ACCESS_TOKEN);
        }
        return token;
    }

    protected String extractHeaderToken(HttpServletRequest request) {
        Enumeration<String> headers = request.getHeaders("Authorization");
        while (headers.hasMoreElements()) {
            String value = headers.nextElement();
            if ((value.toLowerCase().startsWith(OAuth2AccessToken.BEARER_TYPE.toLowerCase()))) {
                String authHeaderValue = value.substring(OAuth2AccessToken.BEARER_TYPE.length()).trim();
                int commaIndex = authHeaderValue.indexOf(',');
                if (commaIndex > 0) {
                    authHeaderValue = authHeaderValue.substring(0, commaIndex);
                }
                return authHeaderValue;
            }
        }

        return null;
    }

    public static class AuthUserProxy {

        private String userId;
        private String username;
        private List<String> authorities = Collections.emptyList();
        private boolean accountNonExpired;
        private boolean accountNonLocked;
        private boolean credentialsNonExpired;
        private boolean enabled;

        private Map details = new HashMap();

        private boolean clientOnly = false;

        public AuthUserProxy(){}

        public AuthUserProxy(AuthUser authUser){
            userId = authUser.getUserId();
            username = authUser.getUsername();
            Collection<GrantedAuthority> authorities = authUser.getAuthorities();
            if(authorities != null){
                this.authorities = new ArrayList<>();
                for (GrantedAuthority authority : authorities) {
                    this.authorities.add(authority.getAuthority());
                }
            }

            accountNonExpired = authUser.isAccountNonExpired();
            accountNonLocked = authUser.isAccountNonLocked();
            credentialsNonExpired = authUser.isCredentialsNonExpired();
            enabled = authUser.isEnabled();
        }

        public Map getDetails() {
            return details;
        }

        public void setDetails(Map details) {
            this.details = details;
        }

        public String getUserId() {
            return userId;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public List<String> getAuthorities() {
            return authorities;
        }

        public void setAuthorities(List<String> authorities) {
            this.authorities = authorities;
        }

        public boolean isAccountNonExpired() {
            return accountNonExpired;
        }

        public void setAccountNonExpired(boolean accountNonExpired) {
            this.accountNonExpired = accountNonExpired;
        }

        public boolean isAccountNonLocked() {
            return accountNonLocked;
        }

        public void setAccountNonLocked(boolean accountNonLocked) {
            this.accountNonLocked = accountNonLocked;
        }

        public boolean isCredentialsNonExpired() {
            return credentialsNonExpired;
        }

        public void setCredentialsNonExpired(boolean credentialsNonExpired) {
            this.credentialsNonExpired = credentialsNonExpired;
        }

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public boolean isClientOnly() {
            return clientOnly;
        }

        public void setClientOnly(boolean clientOnly) {
            this.clientOnly = clientOnly;
        }
    }

    public static class AuthUserContext {
        private static final ThreadLocal<AuthUser> authUserThreadLocal = new ThreadLocal<>();

        private AuthUserContext(){}

        public static void setAuthUser(AuthUser authUser) {
            authUserThreadLocal.set(authUser);
        }

        public static AuthUser getAuthUser() {
            return authUserThreadLocal.get();
        }

        static void reset(){
            authUserThreadLocal.remove();
        }

    }

}
