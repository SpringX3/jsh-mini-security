package jsh.project.minisecurity.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "인증 API")
@RestController
public class AuthSwaggerController {

    @Operation(summary = "로그인", description = "username, password를 입력하면 JWT 토큰이 반환됩니다.")
    @PostMapping("/login")
    public ResponseEntity<String> login(
            @RequestParam String username,
            @RequestParam String password) {
        // 실제 인증은 Filter가 수행하므로 Swagger 표시용 Stub
        return ResponseEntity.ok("로그인 성공 시 JWT 토큰이 반환됩니다.");
    }
}
