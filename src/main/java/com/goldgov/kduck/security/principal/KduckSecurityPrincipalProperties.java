package com.goldgov.kduck.security.principal;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;

import java.util.Set;

public class KduckSecurityPrincipalProperties {


    @ConfigurationProperties(prefix = "kduck.security.oauth2.client.provider")
    public static class SecurityOauth2ClientProviderProperties {

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

    @ConfigurationProperties(prefix = "kduck.security.oauth2.client.registration")
    public static class SecurityOauth2ClientRegistrationProperties {

        private String clientId;
        private String clientSecret;
        private String redirectUri;
        private Set<String> scope;
        private String clientName;
        private String authorizationGrantType;

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getRedirectUri() {
            return redirectUri;
        }

        public void setRedirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
        }

        public Set<String> getScope() {
            return scope;
        }

        public void setScope(Set<String> scope) {
            this.scope = scope;
        }

        public String getClientName() {
            return clientName;
        }

        public void setClientName(String clientName) {
            this.clientName = clientName;
        }

        public String getAuthorizationGrantType() {
            return authorizationGrantType;
        }

        public void setAuthorizationGrantType(String authorizationGrantType) {
            this.authorizationGrantType = authorizationGrantType;
        }
    }


}
