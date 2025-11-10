package jsh.project.minisecurity.security.authentication;

public interface AuthenticationProvider {

    // 처리 가능한 타입인지 확인
    boolean supports(Class<?> authentication);

    Authentication authenticate(Authentication authentication);
}
