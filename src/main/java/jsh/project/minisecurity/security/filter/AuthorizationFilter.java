package jsh.project.minisecurity.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import jsh.project.minisecurity.security.authentication.Authentication;
import jsh.project.minisecurity.security.context.SecurityContextHolder;

public class AuthorizationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain
    ) throws IOException, ServletException {

        // 검사에서 제외
        if (request.getRequestURI().equals("/login") || request.getRequestURI().equals("/")) {
            chain.doFilter(request, response);
            return;
        }

        // SecurityContext에서 Authentication 객체 꺼냄
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // 인증 여부 확인
        if (authentication == null || !authentication.isAuthenticated()) {
            // 로그인 페이지로 리다이렉트
            response.sendRedirect("/login?redirect=" + request.getRequestURI());
            return;
        }

        // 권한 검사
        String uri = request.getRequestURI();
        Collection<String> authorities = authentication.getAuthorities();

        if (uri.startsWith("/admin") && !authorities.contains("ROLE_ADMIN")) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("403: Forbidden");
            return;
        }

        // 통과
        chain.doFilter(request, response);
    }
}
