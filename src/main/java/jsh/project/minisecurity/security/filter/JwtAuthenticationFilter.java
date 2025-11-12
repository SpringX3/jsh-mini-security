package jsh.project.minisecurity.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import jsh.project.minisecurity.security.authentication.Authentication;
import jsh.project.minisecurity.security.authentication.UsernamePasswordAuthenticationToken;
import jsh.project.minisecurity.security.context.SecurityContext;
import jsh.project.minisecurity.security.context.SecurityContextHolder;
import jsh.project.minisecurity.security.jwt.JwtService;

public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain)
            throws IOException, ServletException {

        if (request.getRequestURI().startsWith("/login")) {
            chain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader("Authorization");

        if (authHeader != null || authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);

            try {
                if (!jwtService.isExpired(token)) {
                    String username = jwtService.getUsername(token);
                    List<String> roles = jwtService.getRoles(token);

                    Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, roles);
                    SecurityContext context = new SecurityContext();
                    context.setAuthentication(authentication);
                    SecurityContextHolder.setContext(context);
                }
            } catch (Exception e) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("JWT 오류: " + e.getMessage());
                return;
            }
        }

        chain.doFilter(request, response);
    }
}
