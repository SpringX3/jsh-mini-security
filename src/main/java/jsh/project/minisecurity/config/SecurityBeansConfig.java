package jsh.project.minisecurity.config;

import java.util.List;
import jsh.project.minisecurity.security.authentication.AuthenticationProvider;
import jsh.project.minisecurity.security.authentication.ProviderManager;
import jsh.project.minisecurity.security.authentication.UsernamePasswordAuthenticationProvider;
import jsh.project.minisecurity.security.encoder.BCryptPasswordEncoder;
import jsh.project.minisecurity.security.encoder.PasswordEncoder;
import jsh.project.minisecurity.security.user.InMemoryUserDetailsService;
import jsh.project.minisecurity.security.user.UserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SecurityBeansConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsService();
    }

    @Bean
    public AuthenticationProvider usernamePasswordAuthenticationProvider(
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) {
        return new UsernamePasswordAuthenticationProvider(userDetailsService, passwordEncoder);
    }

    @Bean
    public ProviderManager providerManager(AuthenticationProvider authenticationProvider) {
        return new ProviderManager(List.of(authenticationProvider));
    }
}
