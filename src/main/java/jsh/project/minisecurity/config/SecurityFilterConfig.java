package jsh.project.minisecurity.config;

import jsh.project.minisecurity.security.authentication.ProviderManager;
import jsh.project.minisecurity.security.filter.AuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class SecurityFilterConfig {

    private final ProviderManager providerManager;

    @Bean
    public FilterRegistrationBean<AuthenticationFilter> authenticationFilter() {
        FilterRegistrationBean<AuthenticationFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new AuthenticationFilter(providerManager));
        registration.addUrlPatterns("/*");
        registration.setOrder(1);
        return registration;
    }
}
