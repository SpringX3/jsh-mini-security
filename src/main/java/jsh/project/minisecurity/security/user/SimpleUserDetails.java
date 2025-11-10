package jsh.project.minisecurity.security.user;

import java.util.Collection;

public class SimpleUserDetails implements UserDetails {

    private final String username;
    private final String password;
    private final Collection<String> authorities;

    public SimpleUserDetails(String username, String password, Collection<String> authorities) {
        this.username = username;
        this.password = password;
        this.authorities = authorities;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public Collection<String> getAuthorities() {
        return authorities;
    }
}
