package com.fitcrew.jwt.config;

import com.fitcrew.FitCrewAppConstant.message.type.SecurityContextErrorType;
import com.fitcrew.jwt.util.JWTUtil;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Objects;

@Component
public class SecurityContextRepository implements ServerSecurityContextRepository {
    private final AuthenticationManager authenticationManager;

    public SecurityContextRepository(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Mono<Void> save(ServerWebExchange serverWebExchange,
                           SecurityContext securityContext) {
        throw new UnsupportedOperationException(SecurityContextErrorType.NOT_SUPPORTED_MSG.getMsg());
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange serverWebExchange) {
        var authHeader = serverWebExchange
                .getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        return Mono.justOrEmpty(authHeader)
                .filter(header -> Objects.nonNull(header) && header.startsWith(JWTUtil.BEARER))
                .map(header -> header.substring(7))
                .map(authToken -> new UsernamePasswordAuthenticationToken(authHeader, authToken))
                .flatMap(this::getSecurityContextImpl);
    }

    private Mono<SecurityContextImpl> getSecurityContextImpl(UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken) {
        return authenticationManager.authenticate(usernamePasswordAuthenticationToken)
                .map(SecurityContextImpl::new);
    }

}