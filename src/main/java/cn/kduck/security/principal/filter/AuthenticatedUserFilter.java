package cn.kduck.security.principal.filter;

import cn.kduck.security.UserExtInfo;
import cn.kduck.core.cache.CacheHelper;
import cn.kduck.security.principal.AuthUser;
import cn.kduck.core.service.ValueMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

public class AuthenticatedUserFilter extends OncePerRequestFilter {

    public static final String AUTH_USER_CACHE_NAME = "AUTH_USER";

    private List<AuthUserExtractor> authUserExtractorList;

    @Autowired(required = false)
    private UserExtInfo userExtInfo;

    @Autowired(required = false)
    private List<FilterInterceptor> filterInterceptors;

    public AuthenticatedUserFilter(List<AuthUserExtractor> authUserExtractorList){
        this.authUserExtractorList = authUserExtractorList;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

//        boolean extracted = false;
        for (AuthUserExtractor authUserExtractor : authUserExtractorList) {
            AuthUser authUser = authUserExtractor.extract(request, response);
            if(authUser != null){
//                extracted = true;
                Map extInfo = CacheHelper.getByCacheName(AUTH_USER_CACHE_NAME, authUser.getUsername(),Map.class);
                if(extInfo != null){
                    authUser.setAllDetailsItem(extInfo);
                }else if(userExtInfo != null) {
                    ValueMap userExtInfo = this.userExtInfo.getUserExtInfo(authUser.getUsername());
                    CacheHelper.put(AUTH_USER_CACHE_NAME, authUser.getUsername(),userExtInfo);
                    if(userExtInfo != null){
                        authUser.setAllDetailsItem(userExtInfo);
                    }
                }
                AuthUserContext.setAuthUser(authUser);
                break;
            }
        }

//        if(!extracted){
//            throw new IllegalArgumentException("?????????????????????????????????????????????????????????");
//        }

        if(filterInterceptors != null){
            for (FilterInterceptor filterInterceptor : filterInterceptors) {
                if(!filterInterceptor.preHandle(request,response)){
                    return;
                }
            }
        }

        try{
            filterChain.doFilter(request,response);

            if(filterInterceptors != null){
                for (FilterInterceptor filterInterceptor : filterInterceptors) {
                    filterInterceptor.postHandle(request,response);
                }
            }
        }finally {
            AuthUserContext.reset();
        }

    }

//    private String refreshToken(AuthUserProxy authUserProxy, HttpServletResponse response, HttpServletRequest httpRequest) {
//        Map details = authUserProxy.getDetails();
//        Date expirationDate = new Date(Long.valueOf(details.get("expiration").toString()));
//        String refreshToken = (String) details.get("refresh_token");
//        String accessToken = null;
//        System.out.println(httpRequest.getRequestURI()+"????????????????????????" + expirationDate + ",??????Token???" + refreshToken);
//        if(expirationDate != null && expirationDate.before(new Date(System.currentTimeMillis()+600000))){
//            if(refreshToken != null){
//                Map<String, String> postParameters = new HashMap<>();
//                postParameters.put("client_id", registrationProperties.getClientId());
//                postParameters.put("client_secret", registrationProperties.getClientSecret());
//                postParameters.put("refresh_token", refreshToken);
//
//                String tokenUri = providerProperties.getTokenUri();
//                tokenUri += "?client_id={client_id}&client_secret={client_secret}&grant_type=refresh_token&refresh_token={refresh_token}";
//                Map tokenInfoMap = refreshTokenTemplate.postForObject(tokenUri, null, Map.class, postParameters);
//                System.out.println(tokenInfoMap);
//                accessToken = ValueMapUtils.getValueAsString(tokenInfoMap, "access_token");
//                String refreshTokenValue = ValueMapUtils.getValueAsString(tokenInfoMap, "refresh_token");
//                int expiresInValue = ValueMapUtils.getValueAsInt(tokenInfoMap, "expires_in");
//                Date expiration = new Date(System.currentTimeMillis() + expiresInValue * 1000);
//                //FIXME define new token header
//                response.setHeader("New-Access-Token", accessToken);
//
//                details.put("refresh_token",refreshTokenValue);
//                details.put("expiration",expiration);
//                CacheHelper.put(accessToken + AUTH_USER_SUFFIX,authUserProxy,expiresInValue,3600);
//            }
//        }
//        return accessToken;
//    }

    @Override
    public void destroy() {
        AuthUserContext.reset();
    }

//    protected String extractHeaderUser(HttpServletRequest request) {
//        String userId = request.getHeader(USER_HEADER_NAME);
//        return userId;
//    }
//
//    protected String extractToken(HttpServletRequest request) {
//        String token = extractHeaderToken(request);
//        if (token == null) {
//            token = request.getParameter(OAuth2AccessToken.ACCESS_TOKEN);
//        }
//        return token;
//    }
//
//    protected String extractHeaderToken(HttpServletRequest request) {
//        Enumeration<String> headers = request.getHeaders("Authorization");
//        while (headers.hasMoreElements()) {
//            String value = headers.nextElement();
//            if ((value.toLowerCase().startsWith(OAuth2AccessToken.BEARER_TYPE.toLowerCase()))) {
//                String authHeaderValue = value.substring(OAuth2AccessToken.BEARER_TYPE.length()).trim();
//                int commaIndex = authHeaderValue.indexOf(',');
//                if (commaIndex > 0) {
//                    authHeaderValue = authHeaderValue.substring(0, commaIndex);
//                }
//                return authHeaderValue;
//            }
//        }
//
//        return null;
//    }

    public static class AuthUserProxy {

        private String username;
        private Collection<String> authorities = Collections.emptyList();
        private boolean accountNonExpired;
        private boolean accountNonLocked;
        private boolean credentialsNonExpired;
        private boolean enabled;

        private Map details = new HashMap();

        private boolean clientOnly = false;

        public AuthUserProxy(){}

        public AuthUserProxy(AuthUser authUser){
            username = authUser.getUsername();
//            Collection<String> authorities = authUser.getAuthorities();
//            if(authorities != null){
//                this.authorities = new ArrayList<>();
//                for (GrantedAuthority authority : authorities) {
//                    this.authorities.add(authority.getAuthority());
//                }
//            }

            authorities = authUser.getAuthorities();
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

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public Collection<String> getAuthorities() {
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

//public class AuthenticatedUserFilter extends OncePerRequestFilter {
//
//    public static final String AUTH_USER_SUFFIX = ".AUTH_USER_SUFFIX";
//
//    public static final String USER_HEADER_NAME = "K-User";
//
//    @Autowired
//    private SecurityOauth2ClientProviderProperties providerProperties;
//
//    @Autowired
//    private SecurityOauth2ClientRegistrationProperties registrationProperties;
//
//    @Autowired
//    private RestTemplate restTemplate;
//
//    @Autowired(required = false)
//    private UserExtInfo userExtInfo;
//
//    @Autowired(required = false)
//    private List<FilterInterceptor> filterInterceptors;
//
//    private RestTemplate refreshTokenTemplate = new RestTemplate();
//
//    @Override
//    protected void doFilterInternal(
//            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//            throws ServletException, IOException {
//
//        String accessToken = extractToken(request);
//        if(accessToken != null){
//            //TODO ????????????????????????
//            //TODO ??????token?????????????????????user_info???????????????????????????????????????????????????????????????????????????token????????????????????????????????????????????????
//            //TODO ????????????????????????user_info??????????????????????????????????????????TokenStore???
//            //TODO ????????????????????????????????????????????????IP??????????????????????????????
//
//            String userInfoUri = providerProperties.getUserInfoUri();
//            if (userInfoUri.startsWith("http")){
////                throw new IllegalArgumentException("Oauth2???????????????????????????????????????kduck.security.oauth2.client.provider.userInfoUri??????");
//                URI uri;
//                try {
//                    uri = new URI(userInfoUri);
//                } catch (URISyntaxException e) {
//                    throw new ServletException("user_info???????????????????????????" + userInfoUri,e);
//                }
//
//                if(!request.getRequestURI().equals(uri.getPath())){
//
//
//
//                    AuthUserProxy authUserProxy = CacheHelper.get(accessToken + AUTH_USER_SUFFIX,AuthUserProxy.class);
//
//                    if(authUserProxy == null) {
//
//                        ResponseEntity<AuthUserProxy> authUserEntity;
//                        String userInfoUrl = userInfoUri + "?" + OAuth2AccessToken.ACCESS_TOKEN + "=" + accessToken;
//                        try{
//                            authUserEntity = restTemplate.getForEntity(userInfoUrl, AuthUserProxy.class);
//                        }catch(HttpClientErrorException e){
//                            throw new ServletException("????????????????????????????????????????????????4xx??????CODE=" + e.getRawStatusCode() + "???URL=" + userInfoUrl,e);
//                        }catch(HttpServerErrorException e){
//                            throw new ServletException("????????????????????????????????????????????????5xx??????CODE=" + e.getRawStatusCode() + "???URL=" + userInfoUrl,e);
//                        }
//
//                        authUserProxy = authUserEntity.getBody();
//                        CacheHelper.put(accessToken + AUTH_USER_SUFFIX,authUserProxy,3600);
//                    }
//
//                    //????????????????????????TOKEN
//                    String newToken = refreshToken(authUserProxy, response, request);
//                    if(newToken != null){
//                        accessToken = newToken;
//                    }
//
////                    List<String> authorities = authUserProxy.getAuthorities();
////                    List<GrantedAuthority> authoritiesSet = new ArrayList<>(authorities.size());
////                    if(authorities != null){
////                        for (String authority : authorities) {
////                            authoritiesSet.add(new SimpleGrantedAuthority(authority));
////                        }
////                    }
//                    AuthUser authUser = new AuthUser(authUserProxy.getUsername(),authUserProxy.getAuthorities());
//                    authUser.setAllDetailsItem(authUserProxy.getDetails());
//                    AuthUserContext.setAuthUser(authUser);
//
//                }
//
//            } else {
//                throw new RuntimeException("OAuth2????????????????????????????????????????????????kduck.security.oauth2.client.provider.userInfoUri??????" + userInfoUri);
//            }
//        }else{
//
//            AuthUser authUser = null;
//
//            String headerUser = extractHeaderUser(request);
//            if(StringUtils.hasText(headerUser)){
//                authUser = new AuthUser(headerUser);
//            }else {
//                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//                if(authentication instanceof UsernamePasswordAuthenticationToken){
//                    Object principal = authentication.getPrincipal();
//                    if(principal instanceof AuthUser){
//                        authUser = (AuthUser)principal;
////                    if(userExtInfo != null) {
////                        ValueMap userExtInfo = this.userExtInfo.getUserExtInfo(authUser.getUsername());
////                        authUser.setAllDetailsItem(userExtInfo);
////                    }
////                    AuthUserContext.setAuthUser(authUser);
//
//                    } else if (principal instanceof UserDetails){
//                        UserDetails userDetails = (UserDetails)principal;
//
//                        Collection<? extends GrantedAuthority> grantedAuthorities = userDetails.getAuthorities();
//                        List<String> authorities = new ArrayList<>(grantedAuthorities.size());
//                        if(grantedAuthorities != null){
//                            for (GrantedAuthority authority : grantedAuthorities) {
//                                authorities.add(authority.getAuthority());
//                            }
//                        }
//
//                        authUser = new AuthUser(userDetails.getUsername(),
//                                userDetails.isEnabled(),
//                                userDetails.isAccountNonExpired(),
//                                userDetails.isCredentialsNonExpired(),
//                                userDetails.isAccountNonLocked(),
//                                authorities);
//                    } else {
//                        throw new IllegalArgumentException("??????????????????????????????" + principal);
//                    }
//                } else if(authentication != null && !(authentication instanceof AnonymousAuthenticationToken)){
//                    throw new IllegalArgumentException("????????????????????????????????????" + authentication);
//                }
//            }
//
//            if(authUser != null){
//                if(userExtInfo != null) {
//                    ValueMap userExtInfo = this.userExtInfo.getUserExtInfo(authUser.getUsername());
//                    authUser.setAllDetailsItem(userExtInfo);
//                }
//                AuthUserContext.setAuthUser(authUser);
//            }
//
//        }
//
//        if(filterInterceptors != null){
//            for (FilterInterceptor filterInterceptor : filterInterceptors) {
//                if(!filterInterceptor.preHandle(request,response)){
//                    return;
//                }
//            }
//        }
//
//        try{
//            filterChain.doFilter(request,response);
//
//            if(filterInterceptors != null){
//                for (FilterInterceptor filterInterceptor : filterInterceptors) {
//                    filterInterceptor.postHandle(request,response);
//                }
//            }
//        }finally {
//            AuthUserContext.reset();
//        }
//
//    }
//
//    private String refreshToken(AuthUserProxy authUserProxy, HttpServletResponse response, HttpServletRequest httpRequest) {
//        Map details = authUserProxy.getDetails();
//        Date expirationDate = new Date(Long.valueOf(details.get("expiration").toString()));
//        String refreshToken = (String) details.get("refresh_token");
//        String accessToken = null;
//        System.out.println(httpRequest.getRequestURI()+"????????????????????????" + expirationDate + ",??????Token???" + refreshToken);
//        if(expirationDate != null && expirationDate.before(new Date(System.currentTimeMillis()+600000))){
//            if(refreshToken != null){
//                Map<String, String> postParameters = new HashMap<>();
//                postParameters.put("client_id", registrationProperties.getClientId());
//                postParameters.put("client_secret", registrationProperties.getClientSecret());
//                postParameters.put("refresh_token", refreshToken);
//
//                String tokenUri = providerProperties.getTokenUri();
//                tokenUri += "?client_id={client_id}&client_secret={client_secret}&grant_type=refresh_token&refresh_token={refresh_token}";
//                Map tokenInfoMap = refreshTokenTemplate.postForObject(tokenUri, null, Map.class, postParameters);
//                System.out.println(tokenInfoMap);
//                accessToken = ValueMapUtils.getValueAsString(tokenInfoMap, "access_token");
//                String refreshTokenValue = ValueMapUtils.getValueAsString(tokenInfoMap, "refresh_token");
//                int expiresInValue = ValueMapUtils.getValueAsInt(tokenInfoMap, "expires_in");
//                Date expiration = new Date(System.currentTimeMillis() + expiresInValue * 1000);
//                //FIXME define new token header
//                response.setHeader("New-Access-Token", accessToken);
//
//                details.put("refresh_token",refreshTokenValue);
//                details.put("expiration",expiration);
//                CacheHelper.put(accessToken + AUTH_USER_SUFFIX,authUserProxy,expiresInValue,3600);
//            }
//        }
//        return accessToken;
//    }
//
//    @Override
//    public void destroy() {
//        AuthUserContext.reset();
//    }
//
//    protected String extractHeaderUser(HttpServletRequest request) {
//        String userId = request.getHeader(USER_HEADER_NAME);
//        return userId;
//    }
//
//    protected String extractToken(HttpServletRequest request) {
//        String token = extractHeaderToken(request);
//        if (token == null) {
//            token = request.getParameter(OAuth2AccessToken.ACCESS_TOKEN);
//        }
//        return token;
//    }
//
//    protected String extractHeaderToken(HttpServletRequest request) {
//        Enumeration<String> headers = request.getHeaders("Authorization");
//        while (headers.hasMoreElements()) {
//            String value = headers.nextElement();
//            if ((value.toLowerCase().startsWith(OAuth2AccessToken.BEARER_TYPE.toLowerCase()))) {
//                String authHeaderValue = value.substring(OAuth2AccessToken.BEARER_TYPE.length()).trim();
//                int commaIndex = authHeaderValue.indexOf(',');
//                if (commaIndex > 0) {
//                    authHeaderValue = authHeaderValue.substring(0, commaIndex);
//                }
//                return authHeaderValue;
//            }
//        }
//
//        return null;
//    }
//
//    public static class AuthUserProxy {
//
//        private String username;
//        private Collection<String> authorities = Collections.emptyList();
//        private boolean accountNonExpired;
//        private boolean accountNonLocked;
//        private boolean credentialsNonExpired;
//        private boolean enabled;
//
//        private Map details = new HashMap();
//
//        private boolean clientOnly = false;
//
//        public AuthUserProxy(){}
//
//        public AuthUserProxy(AuthUser authUser){
//            username = authUser.getUsername();
////            Collection<String> authorities = authUser.getAuthorities();
////            if(authorities != null){
////                this.authorities = new ArrayList<>();
////                for (GrantedAuthority authority : authorities) {
////                    this.authorities.add(authority.getAuthority());
////                }
////            }
//
//            authorities = authUser.getAuthorities();
//            accountNonExpired = authUser.isAccountNonExpired();
//            accountNonLocked = authUser.isAccountNonLocked();
//            credentialsNonExpired = authUser.isCredentialsNonExpired();
//            enabled = authUser.isEnabled();
//        }
//
//        public Map getDetails() {
//            return details;
//        }
//
//        public void setDetails(Map details) {
//            this.details = details;
//        }
//
//        public String getUsername() {
//            return username;
//        }
//
//        public void setUsername(String username) {
//            this.username = username;
//        }
//
//        public Collection<String> getAuthorities() {
//            return authorities;
//        }
//
//        public void setAuthorities(List<String> authorities) {
//            this.authorities = authorities;
//        }
//
//        public boolean isAccountNonExpired() {
//            return accountNonExpired;
//        }
//
//        public void setAccountNonExpired(boolean accountNonExpired) {
//            this.accountNonExpired = accountNonExpired;
//        }
//
//        public boolean isAccountNonLocked() {
//            return accountNonLocked;
//        }
//
//        public void setAccountNonLocked(boolean accountNonLocked) {
//            this.accountNonLocked = accountNonLocked;
//        }
//
//        public boolean isCredentialsNonExpired() {
//            return credentialsNonExpired;
//        }
//
//        public void setCredentialsNonExpired(boolean credentialsNonExpired) {
//            this.credentialsNonExpired = credentialsNonExpired;
//        }
//
//        public boolean isEnabled() {
//            return enabled;
//        }
//
//        public void setEnabled(boolean enabled) {
//            this.enabled = enabled;
//        }
//
//        public boolean isClientOnly() {
//            return clientOnly;
//        }
//
//        public void setClientOnly(boolean clientOnly) {
//            this.clientOnly = clientOnly;
//        }
//    }
//
//    public static class AuthUserContext {
//        private static final ThreadLocal<AuthUser> authUserThreadLocal = new ThreadLocal<>();
//
//        private AuthUserContext(){}
//
//        public static void setAuthUser(AuthUser authUser) {
//            authUserThreadLocal.set(authUser);
//        }
//
//        public static AuthUser getAuthUser() {
//            return authUserThreadLocal.get();
//        }
//
//        static void reset(){
//            authUserThreadLocal.remove();
//        }
//
//    }
//
//}
