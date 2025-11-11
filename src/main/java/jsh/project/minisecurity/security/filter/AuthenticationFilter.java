package jsh.project.minisecurity.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import jsh.project.minisecurity.security.authentication.Authentication;
import jsh.project.minisecurity.security.authentication.AuthenticationManager;
import jsh.project.minisecurity.security.authentication.UsernamePasswordAuthenticationToken;
import jsh.project.minisecurity.security.context.SecurityContext;
import jsh.project.minisecurity.security.context.SecurityContextHolder;

public class AuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;

    public AuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws IOException, ServletException {

        // 로그인 요청이 아니면 건너뜀
        if (!request.getRequestURI().equals("/login") ||
                !request.getMethod().equalsIgnoreCase("POST")) {
            chain.doFilter(request, response);
            return;
        }

        // 요청에서 ID/PW 추출
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        if (username == null || password == null) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("username/password가 필요합니다.");
            return;
        }

        // 인증 시도
        Authentication authRequest = new UsernamePasswordAuthenticationToken(username, password);

        try {
            Authentication authResult = authenticationManager.authenticate(authRequest);

            // 성공 시 SecurityContext에 저장
            SecurityContext context = new SecurityContext();
            context.setAuthentication(authResult);
            SecurityContextHolder.setContext(context);

            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().write("로그인 성공: " + username);
        } catch (RuntimeException e) {
            // 실패 시 401 반환
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("인증 실패: " + e.getMessage());
        }
    }
}
