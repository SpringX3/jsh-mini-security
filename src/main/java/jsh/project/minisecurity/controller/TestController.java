package jsh.project.minisecurity.controller;

import jsh.project.minisecurity.security.authentication.Authentication;
import jsh.project.minisecurity.security.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }

    @GetMapping("/me")
    public String me() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated()) {
            return "인증되지 않은 사용자입니다.";
        }

        return String.format("""
                        사용자명: %s
                        권한: %s
                        인증여부: %s
                        """,
                auth.getPrincipal(),
                auth.getAuthorities(),
                auth.isAuthenticated());
    }

    @GetMapping("/admin")
    public String admin() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated()) {
            return "인증되지 않은 사용자입니다.";
        }

        if (!auth.getAuthorities().contains("ROLE_ADMIN")) {
            return "접근 권한이 없습니다.";
        }

        return "관리자 접근이 허용되었습니다.";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/")
    public String home() {
        return "home page";
    }
}
