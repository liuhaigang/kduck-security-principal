package com.goldgov.kduck.security.principal.configuration;

import com.goldgov.kduck.dao.DeleteArchiveHandler;
import com.goldgov.kduck.security.configuration.HttpSecurityConfigurer;
import com.goldgov.kduck.security.principal.KduckSecurityPrincipalProperties.SecurityOauth2ClientProviderProperties;
import com.goldgov.kduck.security.principal.KduckSecurityPrincipalProperties.SecurityOauth2ClientRegistrationProperties;
import com.goldgov.kduck.security.principal.filter.AuthUserExtractor;
import com.goldgov.kduck.security.principal.filter.AuthenticatedUserFilter;
import com.goldgov.kduck.security.principal.filter.extractor.HeaderUserExtractorImpl;
import com.goldgov.kduck.security.principal.filter.extractor.OauthUserExtractorImpl;
import com.goldgov.kduck.security.principal.filter.extractor.SessionUserExtractorImpl;
import com.goldgov.kduck.security.principal.handler.SecurityDeleteArchiveHandler;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.web.filter.GenericFilterBean;

@Configuration
@EnableConfigurationProperties({SecurityOauth2ClientProviderProperties.class, SecurityOauth2ClientRegistrationProperties.class})
public class SecurityPrincipalConfiguration {// extends WebSecurityConfigurerAdapter {

//    @Value("${kduck.security.ignored}")
//    private String[] ignored;

//    @Override
//    public void configure(HttpSecurity http) throws Exception {
//        http.addFilterAfter(authenticatedUserFilter(), ExceptionTranslationFilter.class);
//    }

    @Bean
    public GenericFilterBean authenticatedUserFilter(){
        return new AuthenticatedUserFilter();
    }

    @Bean
    @ConditionalOnMissingBean(DeleteArchiveHandler.class)
    public DeleteArchiveHandler securityDeleteArchiveHandler(){
        return new SecurityDeleteArchiveHandler();
    }

    @Bean
    public AuthUserExtractor headerUserExtractor(){
        return new HeaderUserExtractorImpl();
    }


//    @Override
//    public void configure(WebSecurity web) throws Exception {
////        web.ignoring()
////                .antMatchers("/**/*.png","/**/*.jpg","/**/*.gif","/**/*.bmp")
////                .antMatchers("/**/*.css","/**/*.js")
////
////                .antMatchers("/swagger-ui.html")
////                .antMatchers("/webjars/**")
////                .antMatchers("/v2/**")
////                .antMatchers("/swagger-resources/**")
////                .antMatchers("/error")
////                .antMatchers("/favicon.ico")
//
//                //TODO 该模块中不应该出现业务接口地址
//        web.ignoring().antMatchers("/account/credential/valid");
//
////        if(ignored != null && ignored.length > 0){
////            for (String i : ignored) {
////                web.ignoring().antMatchers(i);
////            }
////        }
//
//    }

    @Configuration
    @ConditionalOnClass(WebSecurity.class)
    @Order(500)
    public class SpringSecurityConfiguration implements HttpSecurityConfigurer {
        //    @Value("${kduck.security.ignored}")
//    private String[] ignored;

        @Bean
        public AuthUserExtractor sessionUserExtractor(){
            return new SessionUserExtractorImpl();
        }

        @Bean
        public AuthUserExtractor oauthUserExtractor(){
            return new OauthUserExtractorImpl();
        }

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http.addFilterAfter(authenticatedUserFilter(), ExceptionTranslationFilter.class);
        }

//        @Bean
//        public GenericFilterBean authenticatedUserFilter(){
//            return new AuthenticatedUserFilter();
//        }
//
//        @Bean
//        @ConditionalOnMissingBean(DeleteArchiveHandler.class)
//        public DeleteArchiveHandler securityDeleteArchiveHandler(){
//            return new SecurityDeleteArchiveHandler();
//        }


        @Override
        public void configure(WebSecurity web) throws Exception {
//        web.ignoring()
//                .antMatchers("/**/*.png","/**/*.jpg","/**/*.gif","/**/*.bmp")
//                .antMatchers("/**/*.css","/**/*.js")
//
//                .antMatchers("/swagger-ui.html")
//                .antMatchers("/webjars/**")
//                .antMatchers("/v2/**")
//                .antMatchers("/swagger-resources/**")
//                .antMatchers("/error")
//                .antMatchers("/favicon.ico")

            //TODO 该模块中不应该出现业务接口地址
            web.ignoring().antMatchers("/account/credential/valid");

//        if(ignored != null && ignored.length > 0){
//            for (String i : ignored) {
//                web.ignoring().antMatchers(i);
//            }
//        }

        }
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
