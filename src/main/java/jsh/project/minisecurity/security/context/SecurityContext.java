package jsh.project.minisecurity.security.context;

import jsh.project.minisecurity.security.authentication.Authentication;

public class SecurityContext {

    private Authentication authentication;  // 인증 정보는 변경될 수 있음

    public Authentication getAuthentication() {
        return authentication;
    }

    public void setAuthentication(Authentication authentication) {
        this.authentication = authentication;
    }
}
