package jsh.project.minisecurity.security.context;

public class SecurityContextHolder {

    // SecurityContext를 ThreadLocal로 저장
    private static final ThreadLocal<SecurityContext> contextHolder = new ThreadLocal<>();

    // SecurityContext 조회
    public static SecurityContext getContext() {
        // Thread에 존재하는 SecurityContext 조회
        SecurityContext context = contextHolder.get();

        // Thread에 없으면 생성
        if (context == null) {
            context = new SecurityContext();
            contextHolder.set(context);
        }

        return context;
    }

    public static void setContext(SecurityContext context) {
        contextHolder.set(context);
    }

    // SecurityContext Clear
    public static void clearContext() {
        contextHolder.remove();
    }
}
