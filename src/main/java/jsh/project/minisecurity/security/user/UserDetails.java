package jsh.project.minisecurity.security.user;

import java.util.Collection;

public interface UserDetails {
    String getUsername();

    String getPassword();

    Collection<String> getAuthorities();
}
