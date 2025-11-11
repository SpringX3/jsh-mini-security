package jsh.project.minisecurity.security.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public abstract class OncePerRequestFilter implements Filter {

    @Override
    public final void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String alreadyFilteredKey = getAlreadyFilteredAttributeName();

        // 이미 실행된 요청인지 확인
        if (request.getAttribute(alreadyFilteredKey) != null) {
            chain.doFilter(request, response);
            return;
        }

        // 실행 표시
        request.setAttribute(alreadyFilteredKey, Boolean.TRUE);

        try {
            // 필터링 로직 실행
            doFilterInternal(httpRequest, httpResponse, chain);
        } finally {
            // 요청 끝나면 플래그 제거
            request.removeAttribute(alreadyFilteredKey);
        }
    }

    // 실제 처리 로직은 서브 클래스에서 구현
    protected abstract void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain)
            throws IOException, ServletException;

    // 중복 실행 방지용 키
    protected String getAlreadyFilteredAttributeName() {
        return getClass().getName() + ".FILTERED";
    }
}
