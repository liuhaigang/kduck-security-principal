package com.goldgov.kduck.security.principal;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;

@ConfigurationProperties(prefix = "kduck.security.oauth2.client.provider")
public class KduckSecurityPrincipalProperties {

    private String hostUri;

    private String authorizationUri = "/oauth/authorize";
    private String tokenUri = "/oauth/token";
    private String userInfoUri = "/oauth/user_info";

    public String getHostUri() {
        if (hostUri.endsWith("/")) {
            return hostUri.substring(0, hostUri.length() - 1);
        }
        return hostUri;
    }

    public void setHostUri(String hostUri) {
        this.hostUri = hostUri;
    }

    public String getAuthorizationUri() {
        if (StringUtils.hasText(hostUri) && !authorizationUri.startsWith("http")) {
            return getHostUri() + authorizationUri;
        }
        return authorizationUri;
    }

    public void setAuthorizationUri(String authorizationUri) {
        this.authorizationUri = authorizationUri;
    }

    public String getTokenUri() {
        if (StringUtils.hasText(hostUri) && !tokenUri.startsWith("http")) {
            return getHostUri() + tokenUri;
        }
        return tokenUri;
    }

    public void setTokenUri(String tokenUri) {
        this.tokenUri = tokenUri;
    }

    public String getUserInfoUri() {
        if (StringUtils.hasText(hostUri) && !userInfoUri.startsWith("http")) {
            return getHostUri() + userInfoUri;
        }
        return userInfoUri;
    }

    public void setUserInfoUri(String userInfoUri) {
        this.userInfoUri = userInfoUri;
    }


}
