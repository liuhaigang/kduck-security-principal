package com.goldgov.kduck.security.principal.configuration;

import com.goldgov.kduck.dao.DeleteArchiveHandler;
import com.goldgov.kduck.security.principal.KduckSecurityPrincipalProperties.SecurityOauth2ClientProviderProperties;
import com.goldgov.kduck.security.principal.KduckSecurityPrincipalProperties.SecurityOauth2ClientRegistrationProperties;
import com.goldgov.kduck.security.principal.filter.AuthenticatedUserFilter;
import com.goldgov.kduck.security.principal.handler.SecurityDeleteArchiveHandler;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.web.filter.GenericFilterBean;

@Configuration
@EnableConfigurationProperties({SecurityOauth2ClientProviderProperties.class, SecurityOauth2ClientRegistrationProperties.class})
@Order(500)
public class SecurityPrincipalConfiguration  extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterAfter(authenticatedUserFilter(), ExceptionTranslationFilter.class);
    }

    @Bean
    public GenericFilterBean authenticatedUserFilter(){
        return new AuthenticatedUserFilter();
    }

    @Bean
    @ConditionalOnMissingBean(DeleteArchiveHandler.class)
    public DeleteArchiveHandler securityDeleteArchiveHandler(){
        return new SecurityDeleteArchiveHandler();
    }

    @Configuration
    @EnableResourceServer
    @ConditionalOnClass(EnableResourceServer.class)
    @ConditionalOnProperty(prefix="kduck.security.oauth2.resServer",name="enabled",havingValue = "true")
    public class OAuthResourceServerConfiguration extends ResourceServerConfigurerAdapter {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            http.addFilterBefore(authenticatedUserFilter(), ExceptionTranslationFilter.class);
        }
    }
}
