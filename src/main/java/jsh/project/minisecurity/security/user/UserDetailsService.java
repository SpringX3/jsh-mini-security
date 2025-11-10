package jsh.project.minisecurity.security.user;

public interface UserDetailsService {
    UserDetails loadUserByUsername(String username);
}
