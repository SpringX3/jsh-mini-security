# Spring Security 직접 구현 (Mini Security Framework)

## 프로젝트 목표

이 구현의 목적은 **Spring Security의 내부 원리를 완전히 이해**하고,
이를 바탕으로 자신만의 **경량 인증/인가 프레임워크**를 구축하는 것이다.

---

## 🧩 전체 개요

Spring Security는 **Filter 기반 보안 프레임워크**다.
모든 요청은 서블릿 이전 단계에서 **Filter Chain**을 통해 인증(Authentication)과 인가(Authorization)을 거친다.

본 구현은 그 구조를 직접 재현한다:

```
[Http 요청]
   ↓
[Filter Chain]
   ↓
 ├── JwtAuthenticationFilter      → JWT 검증
├── AuthenticationFilter          → 로그인 요청 처리
├── AuthorizationFilter           → 접근 권한 검사
   ↓
[DispatcherServlet → Controller]
```

---

## 구현 내용

### Authentication 코어

* `Authentication`, `UsernamePasswordAuthenticationToken`으로 인증 요청/응답 객체를 직접 정의했다.
* `AuthenticationManager`의 구현체인 `ProviderManager`가 등록된 `AuthenticationProvider` 컬렉션을 순회하며 실제 인증을 수행한다.
* `UsernamePasswordAuthenticationProvider`는 `UserDetailsService` + `PasswordEncoder` 조합으로 사용자 조회와 비밀번호 검증을 담당한다.
* `SecurityBeansConfig`가 `BCryptPasswordEncoder`, `InMemoryUserDetailsService`, `ProviderManager` 등을 Bean 으로 노출하고,
  `user/1234`, `admin/admin123` 계정을 미리 메모리에 적재한다.

### 사용자 저장소 & PasswordEncoder

* `UserDetails`, `UserDetailsService`, `SimpleUserDetails`, `InMemoryUserDetailsService`로 최소한의 사용자/권한 모델을 구성했다.
* `PasswordEncoder` 인터페이스를 따라 `BCryptPasswordEncoder`와 `PlainTextPasswordEncoder`를 구현하여 상황에 따라 교체 가능하다.
* In-memory 저장소는 `Map` 기반으로 구성하여 학습 목적에 맞게 간단히 계정을 추가/삭제할 수 있다.

### SecurityContext

* `SecurityContext`와 `SecurityContextHolder`를 직접 구현하여 `ThreadLocal` 기준으로 인증 정보를 보관/초기화한다.
* Filter 구간에서 인증이 성공하면 Context에 `Authentication`을 저장하고, 컨트롤러에서는 그대로 조회해 권한을 확인한다.

### JWT 발급 및 검증

* `JwtService`는 `jjwt` 라이브러리를 사용해 HS256 비밀키 서명, roles claim, 만료시간(`1h`)을 포함한 토큰을 생성/검증한다.
* `AuthenticationFilter`는 `/login` POST 요청에서 username/password를 추출 → ProviderManager.authenticate() → 성공 시 JWT를 응답으로
  반환한다.
* `JwtAuthenticationFilter`는 모든 요청의 `Authorization` 헤더를 파싱해 토큰을 검증하고, 성공 시 `SecurityContextHolder`에 인증 객체를 적재한다.

### Filter Chain 구성

* `OncePerRequestFilter`를 만들어 각 Filter가 요청 당 한 번만 실행되도록 공통 템플릿을 제공한다.
* `SecurityFilterConfig`에서 `JwtAuthenticationFilter` → `AuthenticationFilter` → `AuthorizationFilter` 순서로
  `FilterRegistrationBean`을 등록했다.
* `AuthorizationFilter`는 `SecurityContextHolder`에서 인증 상태를 확인하고 `/admin` 접근 시 `ROLE_ADMIN` 권한이 있는지 검증한다.
* `SecurityWhitelist`는 `/`, `/login`, Swagger 관련 URL 등을 화이트리스트로 선언해 인증이 없어도 통과하도록 한다.

### 컨트롤러 & 화면

* `LoginController`는 간단한 로그인 페이지(`templates/login.html`) 렌더링과 redirect 파라미터 전달만 담당한다.
* `TestController`는 `/hello`, `/me`, `/admin`, `/` 엔드포인트 예제로 SecurityContext 값을 확인하거나 권한 검사를 시연한다.
* Swagger 테스트 편의를 위해 `AuthSwaggerController`를 추가하여 `/login` 엔드포인트를 문서화했다(실제 인증은 Filter에서 처리).

---

## ⚙️ 핵심 구성 요소

### 1. Authentication 구조

* **Authentication 인터페이스**
  인증 정보를 담는 객체.
  principal(사용자 정보), credentials(비밀번호), authorities(권한 목록), authenticated 여부를 가진다.

* **UsernamePasswordAuthenticationToken**

  ```java
  new UsernamePasswordAuthenticationToken(username, password);
  new UsernamePasswordAuthenticationToken(username, password, authorities);
  ```

  로그인 요청 시 "인증 전" 상태로 생성되며, 인증 성공 후 "인증 완료" 상태로 갱신된다.

* **AuthenticationManager / ProviderManager**
  인증 요청을 전달받아 실제 인증 로직을 수행할 `AuthenticationProvider`를 선택한다.

* **AuthenticationProvider**
  사용자 정보를 확인하고 비밀번호를 검증한다.
  내부적으로 `UserDetailsService`와 `PasswordEncoder`를 사용한다.

---

### 2. 사용자 정보 관리

* **UserDetails**
  인증 대상 사용자의 정보를 표현하는 인터페이스.

* **UserDetailsService**
  사용자 이름으로 `UserDetails`를 로드하는 인터페이스.
  학습용 구현체로 `InMemoryUserDetailsService`를 작성.

  ```java
  Map<String, UserDetails> users = new HashMap<>();
  users.put("user", new SimpleUserDetails("user", encodedPw, List.of("ROLE_USER")));
  ```

* **PasswordEncoder**
  비밀번호를 해시화하여 저장하고, 로그인 시 평문 비밀번호를 검증한다.

  ```java
  boolean matches(String raw, String encoded);
  ```

---

### 3. SecurityContextHolder

* 인증 정보를 **ThreadLocal**에 저장한다.
* 요청 단위로 Authentication을 유지하고, 요청 종료 시 `clearContext()`로 초기화된다.

요청 간 인증을 유지하려면 세션이나 JWT와 같은 별도의 토큰 저장소를 사용해야 한다.

---

## 🔒 JWT 기반 인증

### JWT 구조

JWT(JSON Web Token)는 세션을 사용하지 않고 인증 상태를 유지하는 서명된 토큰이다.

```
Header.Payload.Signature
```

| 구성        | 설명                          |
|-----------|-----------------------------|
| Header    | 서명 알고리즘, 토큰 타입              |
| Payload   | 사용자 식별자(sub), 권한, 만료시간(exp) |
| Signature | 서버의 secret key로 서명 (변조 방지)  |

예시 Payload:

```json
{
  "sub": "user01",
  "role": "ROLE_USER",
  "exp": 1731390000
}
```

---

### JWT 흐름

```
1️⃣ 로그인 요청 (/login)
     ↓
2️⃣ AuthenticationManager.authenticate()
     ↓
3️⃣ 인증 성공 → JWT 발급
     ↓
4️⃣ 클라이언트는 JWT를 Authorization 헤더로 전송
     ↓
5️⃣ JwtAuthenticationFilter가 서명 검증 및 사용자 정보 복원
```

---

### JWT 관련 클래스

#### JwtService

* JWT 생성 및 검증 담당
* 서명 키를 통해 변조 여부를 확인
* 토큰 만료 시간, Claims 추출 기능 포함

#### JwtAuthenticationFilter

* 모든 요청에서 `Authorization: Bearer <token>` 헤더를 확인
* 유효한 토큰이면 `SecurityContextHolder`에 인증 정보 등록
* `/login` 및 토큰이 없는 요청은 필터를 통과시킴

#### AuthenticationFilter

* `/login` 요청에서 username/password 파라미터를 추출
* 인증 성공 시 JWT 발급 및 응답 반환

#### AuthorizationFilter

* `SecurityContextHolder`의 인증 정보 확인
* 인증되지 않았으면 401, 권한 부족 시 403 반환

---

## 🌐 Swagger 설정

### Swagger 연동

JWT 기반 API를 Swagger-UI에서 테스트 가능하도록 설정한다.

```java

@Bean
public OpenAPI openAPI() {
    return new OpenAPI()
            .components(new Components().addSecuritySchemes("bearer-key",
                    new SecurityScheme().type(SecurityScheme.Type.HTTP).scheme("bearer").bearerFormat("JWT")))
            .addSecurityItem(new SecurityRequirement().addList("bearer-key"))
            .info(new Info().title("Mini Security API").version("1.0"));
}
```

---

## 📚 전체 흐름 정리

```
[1] POST /login
     ↓
AuthenticationFilter → ProviderManager → UserDetailsService → PasswordEncoder → JWT 발급
     ↓
HTTP 200 + {"token":"...jwt..."}

[2] 이후 요청
Authorization: Bearer <token>
     ↓
JwtAuthenticationFilter → JWT 검증 및 인증 객체 복원
     ↓
AuthorizationFilter → 권한 체크
     ↓
Controller 실행
```
