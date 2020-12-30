package com.fitcrew.jwt.util;


import com.fitcrew.jwt.model.AuthenticationRequest;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import javax.annotation.PostConstruct;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JWTUtil {

	public static final String BEARER = "Bearer ";
	private static final String AUTHORITIES_KEY = "system";
	private static final String ROLES_KEY = "roles";
	private static final String EMAIL_KEY = "email";

	@Value("${jjwt.secret}")
	private String secret;
	@Value("${jjwt.expiration}")
	private String expiration;

	private Key key;

	@PostConstruct
	public void init() {
		this.key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
	}

	public Mono<String> getAuthenticationToken() {
		return ReactiveSecurityContextHolder.getContext()
				.map(SecurityContext::getAuthentication)
				.map(Authentication::getCredentials)
				.map(token -> BEARER + token)
				.cast(String.class);
	}

	public String createDefaultToken(String systemName) {

		long now = (new Date()).getTime();
		Date validity = new Date(now + 300_000_000_000L);

		return Jwts.builder()
				.setSubject(systemName)
				.claim(AUTHORITIES_KEY, "SYSTEM")
				.signWith(SignatureAlgorithm.HS256, secret)
				.setExpiration(validity)
				.compact();
	}

	public String generateToken(AuthenticationRequest authenticationRequest) {
		Map<String, Object> claims = new HashMap<>();
		claims.put(ROLES_KEY, authenticationRequest.getRole());
		claims.put(EMAIL_KEY, authenticationRequest.getEmail());
		return doGenerateToken(claims, authenticationRequest.getEmail());
	}

	public Boolean validateToken(String token) {
		return !isTokenExpired(token);
	}

	public Claims getAllClaimsFromToken(String token) {
		return Jwts.parserBuilder()
				.setSigningKey(secret)
				.build()
				.parseClaimsJws(token)
				.getBody();
	}

	private Boolean isTokenExpired(String token) {
		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());
	}

	private Date getExpirationDateFromToken(String token) {
		return getAllClaimsFromToken(token).getExpiration();
	}

	private String doGenerateToken(Map<String, Object> claims,
								   String username) {
		var expirationTimeLong = Long.parseLong(expiration);
		final var createdDate = new Date();
		final var expirationDate = new Date(createdDate.getTime() + expirationTimeLong * 1000);
		return Jwts.builder()
				.setClaims(claims)
				.setSubject(username)
				.setIssuedAt(createdDate)
				.setExpiration(expirationDate)
				.signWith(key)
				.compact();
	}

}
