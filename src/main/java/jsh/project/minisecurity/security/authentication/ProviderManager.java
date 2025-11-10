package jsh.project.minisecurity.security.authentication;

import java.util.List;

public class ProviderManager implements AuthenticationManager {

    private final List<AuthenticationProvider> providers;

    public ProviderManager(List<AuthenticationProvider> providers) {
        this.providers = providers;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        // 각 Provider 순회
        for (AuthenticationProvider provider : providers) {
            // 지원하는 타입인지 확인
            if (provider.supports(authentication.getClass())) {
                // 인증 시도
                Authentication result = provider.authenticate(authentication);

                // 인증 성공 시 결과 반환
                if (result != null && result.isAuthenticated()) {
                    return result;
                }
            }
        }

        // 성공한 Provider가 없을 시 예외 throw
        throw new RuntimeException("인증 실패: 지원하는 Provider 없음 또는 검증 실패");
    }
}
