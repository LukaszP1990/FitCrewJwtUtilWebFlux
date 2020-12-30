package com.fitcrew.jwt.config;

import com.fitcrew.FitCrewAppConstant.message.type.RoleType;
import com.fitcrew.jwt.util.JWTUtil;
import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import io.vavr.Tuple;
import io.vavr.Tuple2;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.Objects;

@Component
public class AuthenticationManager implements ReactiveAuthenticationManager {

    private final JWTUtil jwtUtil;

    public AuthenticationManager(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    @SuppressWarnings("unchecked")
    public Mono<Authentication> authenticate(Authentication authentication) {
        var authToken = authentication.getCredentials().toString();
        var claims = jwtUtil.getAllClaimsFromToken(authToken);

        return Mono.justOrEmpty(jwtUtil.validateToken(authToken))
                .filter(result -> result)
                .map(result -> claims)
                .filter(claimsList -> Objects.nonNull(claimsList.get("roles", String.class)))
                .map(this::getTupleOfClaims)
                .map(this::getGrantedAuthority)
                .filter(grantedAuthority -> !RoleType.ROLE_UNDEFINED.name().equals(grantedAuthority.getAuthority()))
                .map(authorities -> getUsernamePasswordAuthenticationToken(claims, authorities));
    }

    private Tuple2<String, String> getTupleOfClaims(Claims claimsList) {
        return Tuple.of(claimsList.get("roles", String.class), claimsList.get("email", String.class));
    }

    private GrantedAuthority getGrantedAuthority(Tuple2<String, String> tupleOfClaims) {
        return Objects.nonNull(tupleOfClaims._1) &&  Objects.nonNull(tupleOfClaims._2)?
                new SimpleGrantedAuthority(tupleOfClaims._1) :
                new SimpleGrantedAuthority(RoleType.ROLE_UNDEFINED.name());
    }

    private UsernamePasswordAuthenticationToken getUsernamePasswordAuthenticationToken(Claims claims,
                                                                                       GrantedAuthority authority) {
        return new UsernamePasswordAuthenticationToken(claims.getSubject(), null, Collections.singletonList(authority));
    }

}