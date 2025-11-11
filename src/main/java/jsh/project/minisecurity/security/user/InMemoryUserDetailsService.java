package jsh.project.minisecurity.security.user;

import java.util.HashMap;
import java.util.Map;

public class InMemoryUserDetailsService implements UserDetailsService {

    private final Map<String, UserDetails> users = new HashMap<>();

    public void addUser(UserDetails user) {
        users.put(user.getUsername(), user);
    }

    public UserDetails loadUserByUsername(String username) {
        return users.get(username);
    }
}
