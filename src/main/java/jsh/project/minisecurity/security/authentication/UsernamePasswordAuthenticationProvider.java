package jsh.project.minisecurity.security.authentication;

import jsh.project.minisecurity.security.encoder.PasswordEncoder;
import jsh.project.minisecurity.security.user.UserDetails;
import jsh.project.minisecurity.security.user.UserDetailsService;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class UsernamePasswordAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        String username = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        // 사용자 조회
        UserDetails user = userDetailsService.loadUserByUsername(username);
        if (user == null) {
            throw new RuntimeException("사용자를 찾을 수 없음");
        }

        // 비밀번호 검증
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("비밀번호 불일치");
        }

        // 성공 시 인증 객체 반환
        return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
    }
}
