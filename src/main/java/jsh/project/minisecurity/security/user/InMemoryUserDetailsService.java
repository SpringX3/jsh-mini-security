package jsh.project.minisecurity.security.user;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import jsh.project.minisecurity.security.encoder.BCryptPasswordEncoder;
import jsh.project.minisecurity.security.encoder.PasswordEncoder;

public class InMemoryUserDetailsService implements UserDetailsService {

    private final Map<String, UserDetails> users = new HashMap<>();

    public InMemoryUserDetailsService() {
        PasswordEncoder encoder = new BCryptPasswordEncoder();

        // 테스트용 유저 데이터 추가
        users.put("user", new SimpleUserDetails(
                "user",
                encoder.encode("1234"),
                List.of("ROLE_USER")
        ));

        users.put("admin", new SimpleUserDetails(
                "admin",
                encoder.encode("admin123"),
                List.of("ROLE_ADMIN")
        ));
    }

    public UserDetails loadUserByUsername(String username) {
        return users.get(username);
    }
}
