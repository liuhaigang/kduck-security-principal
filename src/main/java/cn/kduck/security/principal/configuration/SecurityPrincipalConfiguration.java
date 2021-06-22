package cn.kduck.security.principal.configuration;

import cn.kduck.security.principal.KduckSecurityPrincipalProperties.SecurityOauth2ClientProviderProperties;
import cn.kduck.security.principal.KduckSecurityPrincipalProperties.SecurityOauth2ClientRegistrationProperties;
import cn.kduck.security.principal.filter.AuthUserExtractor;
import cn.kduck.security.principal.filter.AuthenticatedUserFilter;
import cn.kduck.security.principal.filter.extractor.HeaderUserExtractorImpl;
import cn.kduck.security.principal.filter.extractor.OauthUserExtractorImpl;
import cn.kduck.security.principal.filter.extractor.SessionUserExtractorImpl;
import cn.kduck.security.principal.handler.SecurityDeleteArchiveHandler;
import cn.kduck.core.dao.DeleteArchiveHandler;
import cn.kduck.security.configuration.HttpSecurityConfigurer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.access.ExceptionTranslationFilter;

import java.util.List;

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
    public AuthenticatedUserFilter authenticatedUserFilter(List<AuthUserExtractor> authUserExtractorList){
        return new AuthenticatedUserFilter(authUserExtractorList);
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

    @Bean
    public AuthUserExtractor oauthUserExtractor(){
        return new OauthUserExtractorImpl();
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
    @ConditionalOnMissingClass("org.springframework.security.config.annotation.web.builders.WebSecurity")
    public static class KduckSecurityConfiguration {

        @Bean
        public FilterRegistrationBean kduckAuthenticatedUserFilter(AuthenticatedUserFilter authenticatedUserFilter) {
            FilterRegistrationBean registrationBean = new FilterRegistrationBean();
            registrationBean.setOrder(500);
            registrationBean.setFilter(authenticatedUserFilter);
            registrationBean.addUrlPatterns("/*");
            return registrationBean;
        }
    }

    @Configuration
    @ConditionalOnClass(WebSecurity.class)
    @Order(500)
    public static class SpringSecurityConfiguration implements HttpSecurityConfigurer {

        @Autowired
        @Lazy
        private AuthenticatedUserFilter authenticatedUserFilter;

        @Bean
        @ConditionalOnMissingBean(type={
                "org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter",
                "org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer"})
        public AuthUserExtractor sessionUserExtractor(){
            return new SessionUserExtractorImpl();
        }

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http.addFilterAfter(authenticatedUserFilter, ExceptionTranslationFilter.class);
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

        }
    }

    @Configuration
    @EnableResourceServer
    @ConditionalOnClass({ResourceServerConfigurerAdapter.class,EnableResourceServer.class})
    @ConditionalOnProperty(prefix="kduck.security.oauth2.resServer",name="enabled",havingValue = "true")
    public static class OAuthResourceServerConfiguration extends ResourceServerConfigurerAdapter {

        @Autowired
        private AuthenticatedUserFilter authenticatedUserFilter;

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http.addFilterBefore(authenticatedUserFilter, ExceptionTranslationFilter.class);
        }
    }
}
