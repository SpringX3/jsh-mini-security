package jsh.project.minisecurity.security.filter;

import java.util.List;

public final class SecurityWhitelist {

    private static final List<String> EXACT_MATCHES = List.of(
            "/",
            "/login"
    );

    private static final List<String> PREFIX_MATCHES = List.of(
            "/swagger-ui",
            "/v3/api-docs",
            "/swagger-resources",
            "/webjars"
    );

    private SecurityWhitelist() {
    }

    public static boolean matches(String uri) {
        return EXACT_MATCHES.contains(uri) ||
                PREFIX_MATCHES.stream().anyMatch(uri::startsWith);
    }
}
