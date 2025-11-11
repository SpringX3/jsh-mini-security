package jsh.project.minisecurity.config;

import java.util.List;
import jsh.project.minisecurity.security.authentication.AuthenticationProvider;
import jsh.project.minisecurity.security.authentication.ProviderManager;
import jsh.project.minisecurity.security.authentication.UsernamePasswordAuthenticationProvider;
import jsh.project.minisecurity.security.encoder.BCryptPasswordEncoder;
import jsh.project.minisecurity.security.encoder.PasswordEncoder;
import jsh.project.minisecurity.security.user.InMemoryUserDetailsService;
import jsh.project.minisecurity.security.user.SimpleUserDetails;
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
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        InMemoryUserDetailsService service = new InMemoryUserDetailsService();

        service.addUser(new SimpleUserDetails(
                "user",
                passwordEncoder.encode("1234"),
                List.of("ROLE_USER")
        ));
        service.addUser(new SimpleUserDetails(
                "admin",
                passwordEncoder.encode("admin123"),
                List.of("ROLE_ADMIN")
        ));

        return service;
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
