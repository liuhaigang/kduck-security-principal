package com.goldgov.kduck.security.principal.filter.extractor;

import com.goldgov.kduck.cache.CacheHelper;
import com.goldgov.kduck.security.principal.AuthUser;
import com.goldgov.kduck.security.principal.KduckSecurityPrincipalProperties.SecurityOauth2ClientProviderProperties;
import com.goldgov.kduck.security.principal.KduckSecurityPrincipalProperties.SecurityOauth2ClientRegistrationProperties;
import com.goldgov.kduck.security.principal.filter.AuthUserExtractor;
import com.goldgov.kduck.security.principal.filter.AuthenticatedUserFilter.AuthUserProxy;
import com.goldgov.kduck.utils.ValueMapUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class OauthUserExtractorImpl implements AuthUserExtractor {

    public static final String AUTH_USER_SUFFIX = ".AUTH_USER_SUFFIX";

    public static final String ACCESS_TOKEN = "access_token";

    public static final String BEARER_TYPE = "Bearer";

    @Autowired
    private SecurityOauth2ClientProviderProperties providerProperties;

    @Autowired
    private SecurityOauth2ClientRegistrationProperties registrationProperties;

    @Autowired
    private RestTemplate restTemplate;

    private RestTemplate refreshTokenTemplate = new RestTemplate();

    @Override
    public AuthUser extract(HttpServletRequest request, HttpServletResponse response) throws ServletException {
        String accessToken = extractToken(request);
        if (accessToken != null) {
            //TODO 先判断缓存有没有
            //TODO 根据token调用认证服务的user_info接口得到认证用户并缓存，如果得到返回错误信息，比如token过期或无效，需要同时清除对应缓存
            //TODO 如果没配置客户端user_info链接，默认执行本地请求或使用TokenStore？
            //TODO 创建登录成功事件，设置登录时间、IP以及清除登录失败记录

            String userInfoUri = providerProperties.getUserInfoUri();
            if (userInfoUri.startsWith("http")) {
//                throw new IllegalArgumentException("Oauth2调用获取用户接口失败，缺少kduck.security.oauth2.client.provider.userInfoUri配置");
                URI uri;
                try {
                    uri = new URI(userInfoUri);
                } catch (URISyntaxException e) {
                    throw new ServletException("user_info的链接格式不合法：" + userInfoUri, e);
                }

                if (!request.getRequestURI().equals(uri.getPath())) {

                    AuthUserProxy authUserProxy = CacheHelper.get(accessToken + AUTH_USER_SUFFIX, AuthUserProxy.class);

                    if (authUserProxy == null) {

                        ResponseEntity<AuthUserProxy> authUserEntity;
                        String userInfoUrl = userInfoUri + "?" + ACCESS_TOKEN + "=" + accessToken;
                        try {
                            authUserEntity = restTemplate.getForEntity(userInfoUrl, AuthUserProxy.class);
                        } catch (HttpClientErrorException e) {
                            throw new ServletException("调用用户信息接口返回客户端错误（4xx）：CODE=" + e.getRawStatusCode() + "，URL=" + userInfoUrl, e);
                        } catch (HttpServerErrorException e) {
                            throw new ServletException("调用用户信息接口返回服务端错误（5xx）：CODE=" + e.getRawStatusCode() + "，URL=" + userInfoUrl, e);
                        }

                        authUserProxy = authUserEntity.getBody();
                        CacheHelper.put(accessToken + AUTH_USER_SUFFIX, authUserProxy, 3600);
                    }

                    //判断是否需要刷新TOKEN
                    String newToken = refreshToken(authUserProxy, response, request);
                    if (newToken != null) {
                        accessToken = newToken;
                        CacheHelper.put(accessToken + AUTH_USER_SUFFIX, authUserProxy, 3600);
                    }

//                    List<String> authorities = authUserProxy.getAuthorities();
//                    List<GrantedAuthority> authoritiesSet = new ArrayList<>(authorities.size());
//                    if(authorities != null){
//                        for (String authority : authorities) {
//                            authoritiesSet.add(new SimpleGrantedAuthority(authority));
//                        }
//                    }
                    AuthUser authUser = new AuthUser(authUserProxy.getUsername(), authUserProxy.getAuthorities());
                    authUser.setAllDetailsItem(authUserProxy.getDetails());
                    authUser.setDetailsItem("token", accessToken);
//                    AuthUserContext.setAuthUser(authUser);
                    return authUser;

                }

            } else {
                throw new RuntimeException("OAuth2的用户信息接口未配置或配置错误（kduck.security.oauth2.client.provider.userInfoUri）：" + userInfoUri);
            }
        }
        return null;
    }

    private String refreshToken(AuthUserProxy authUserProxy, HttpServletResponse response, HttpServletRequest httpRequest) {
        Map details = authUserProxy.getDetails();
        if (details.isEmpty()) {
            return null;
        }
        Date expirationDate = new Date(Long.valueOf(details.get("expiration").toString()));
        String refreshToken = (String) details.get("refresh_token");
        String accessToken = null;
        System.out.println(httpRequest.getRequestURI() + "，令牌过期时间：" + expirationDate + ",刷新Token：" + refreshToken);
        if (expirationDate != null && expirationDate.before(new Date(System.currentTimeMillis() + 600000))) {
            if (refreshToken != null) {
                Map<String, String> postParameters = new HashMap<>();
                postParameters.put("client_id", registrationProperties.getClientId());
                postParameters.put("client_secret", registrationProperties.getClientSecret());
                postParameters.put("refresh_token", refreshToken);

                String tokenUri = providerProperties.getTokenUri();
                tokenUri += "?client_id={client_id}&client_secret={client_secret}&grant_type=refresh_token&refresh_token={refresh_token}";
                Map tokenInfoMap = refreshTokenTemplate.postForObject(tokenUri, null, Map.class, postParameters);
                System.out.println(tokenInfoMap);
                accessToken = ValueMapUtils.getValueAsString(tokenInfoMap, "access_token");
                String refreshTokenValue = ValueMapUtils.getValueAsString(tokenInfoMap, "refresh_token");
                int expiresInValue = ValueMapUtils.getValueAsInt(tokenInfoMap, "expires_in");
                Date expiration = new Date(System.currentTimeMillis() + expiresInValue * 1000);
                //FIXME define new token header
                response.setHeader("New-Access-Token", accessToken);

                details.put("refresh_token", refreshTokenValue);
                details.put("expiration", expiration);
                CacheHelper.put(accessToken + AUTH_USER_SUFFIX, authUserProxy, expiresInValue, 3600);
            }
        }
        return accessToken;
    }

    protected String extractToken(HttpServletRequest request) {
        String token = extractHeaderToken(request);
        if (token == null) {
            token = request.getParameter(ACCESS_TOKEN);
        }
        return token;
    }

    protected String extractHeaderToken(HttpServletRequest request) {
        Enumeration<String> headers = request.getHeaders("Authorization");
        while (headers.hasMoreElements()) {
            String value = headers.nextElement();
            if ((value.toLowerCase().startsWith(BEARER_TYPE.toLowerCase()))) {
                String authHeaderValue = value.substring(BEARER_TYPE.length()).trim();
                int commaIndex = authHeaderValue.indexOf(',');
                if (commaIndex > 0) {
                    authHeaderValue = authHeaderValue.substring(0, commaIndex);
                }
                return authHeaderValue;
            }
        }

        return null;
    }
}
