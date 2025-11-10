package jsh.project.minisecurity.security.authentication;

import java.util.Collection;

public interface Authentication {
    Object getPrincipal();

    Object getCredentials();

    Collection<String> getAuthorities();

    boolean isAuthenticated();

    void setAuthenticated(boolean isAuthenticated);
}
