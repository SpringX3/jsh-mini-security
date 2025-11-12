package jsh.project.minisecurity.config;

import jsh.project.minisecurity.security.authentication.ProviderManager;
import jsh.project.minisecurity.security.filter.AuthenticationFilter;
import jsh.project.minisecurity.security.filter.AuthorizationFilter;
import jsh.project.minisecurity.security.filter.JwtAuthenticationFilter;
import jsh.project.minisecurity.security.jwt.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class SecurityFilterConfig {

    private final ProviderManager providerManager;

    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtFilter(JwtService jwtService) {
        FilterRegistrationBean<JwtAuthenticationFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new JwtAuthenticationFilter(jwtService));
        registration.addUrlPatterns("/*");
        registration.setOrder(1);
        return registration;
    }

    @Bean
    public FilterRegistrationBean<AuthenticationFilter> authenticationFilter(
            ProviderManager providerManager,
            JwtService jwtService) {
        FilterRegistrationBean<AuthenticationFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new AuthenticationFilter(providerManager, jwtService));
        registration.addUrlPatterns("/*");
        registration.setOrder(2);
        return registration;
    }

    @Bean
    public FilterRegistrationBean<AuthorizationFilter> authorizationFilter() {
        FilterRegistrationBean<AuthorizationFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new AuthorizationFilter());
        registration.addUrlPatterns("/*");
        registration.setOrder(3);   // AuthenticationFilter 다음 순서
        return registration;
    }
}
