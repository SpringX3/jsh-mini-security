package jsh.project.minisecurity.security.authentication;

import java.util.Collection;

public class UsernamePasswordAuthenticationToken implements Authentication {

    private final Object principal;
    private Object credentials;
    private Collection<String> authorities;
    private boolean authenticated = false;

    // 인증 전(시도)
    public UsernamePasswordAuthenticationToken(Object principal, Object credentials) {
        this.principal = principal;
        this.credentials = credentials;
        this.authenticated = false;
    }

    // 인증 후(인증 성공)
    public UsernamePasswordAuthenticationToken(Object principal, Object credentials, Collection<String> authorities) {
        this.principal = principal;
        this.credentials = credentials;
        this.authorities = authorities;
        this.authenticated = true;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Collection<String> getAuthorities() {
        return authorities;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) {
        this.authenticated = isAuthenticated;
    }
}
