package com.fitcrew.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class WebSecurityConfig {

    private static final String CLIENT_PATH = "/api/client";
    private static final String TRAINER_PATH = "/api/trainer";
    private static final String ADMIN_PATH = "/api/admin";
    private static final String LOGIN_PATH = "/login";
    private static final String SIGN_UP_PATH = "/sign-up";
    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;

    public WebSecurityConfig(AuthenticationManager authenticationManager,
                             SecurityContextRepository securityContextRepository) {
        this.authenticationManager = authenticationManager;
        this.securityContextRepository = securityContextRepository;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .authenticationManager(authenticationManager)
                .securityContextRepository(securityContextRepository)
                .authorizeExchange()
                .pathMatchers(HttpMethod.OPTIONS).permitAll()
                .pathMatchers(CLIENT_PATH.concat(LOGIN_PATH)).permitAll()
                .pathMatchers(CLIENT_PATH.concat(SIGN_UP_PATH)).permitAll()
                .pathMatchers(TRAINER_PATH.concat(LOGIN_PATH)).permitAll()
                .pathMatchers(TRAINER_PATH.concat(SIGN_UP_PATH)).permitAll()
                .pathMatchers(ADMIN_PATH.concat(LOGIN_PATH)).permitAll()
                .pathMatchers(ADMIN_PATH.concat(SIGN_UP_PATH)).permitAll()
                .anyExchange().authenticated()
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(getServerAuthenticationEntryPoint())
                .accessDeniedHandler(getServerAccessDeniedHandler())
                .and()
                .build();
    }

    private ServerAccessDeniedHandler getServerAccessDeniedHandler() {
        return (serverWebExchange, accessDeniedException) ->
                Mono.fromRunnable(() -> isHttpStatus(serverWebExchange, HttpStatus.FORBIDDEN));
    }

    private ServerAuthenticationEntryPoint getServerAuthenticationEntryPoint() {
        return (serverWebExchange, authenticationException) ->
                Mono.fromRunnable(() -> isHttpStatus(serverWebExchange, HttpStatus.UNAUTHORIZED));
    }

    private void isHttpStatus(ServerWebExchange serverWebExchange,
                              HttpStatus httpStatus) {
        serverWebExchange
                .getResponse()
                .setStatusCode(httpStatus);
    }

}
