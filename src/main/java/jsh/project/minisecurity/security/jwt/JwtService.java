package jsh.project.minisecurity.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import java.util.List;
import javax.crypto.SecretKey;

public class JwtService {
    private final SecretKey key = Keys.hmacShaKeyFor("MySuperSecretKeyForJwtExample12345".getBytes());
    private final long EXPIRATION_TIME = 1000L * 60 * 60;

    public String generateToken(String username, List<String> roles) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .subject(username)
                .claim("roles", roles)
                .issuedAt(new Date(now))
                .expiration(new Date(now + EXPIRATION_TIME))
                .signWith(key)
                .compact();
    }

    public Jws<Claims> parseToken(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token);
    }

    public String getUsername(String token) {
        return parseToken(token).getPayload().getSubject();
    }

    public List<String> getRoles(String token) {
        return parseToken(token).getPayload().get("roles", List.class);
    }

    public boolean isExpired(String token) {
        return parseToken(token).getPayload().getExpiration().before(new Date());
    }
}
