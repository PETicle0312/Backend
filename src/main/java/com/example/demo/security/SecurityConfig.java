package com.example.demo.security;

import static org.springframework.security.authorization.AuthorityAuthorizationManager.*;

import jakarta.servlet.DispatcherType;

import org.springframework.context.annotation.*;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.NullSecurityContextRepository;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {
    @Bean
    org.springframework.web.cors.CorsConfigurationSource corsSource(
            @org.springframework.beans.factory.annotation.Value("${security.cors.allowed-origins:}")
                    String origins) {
        var config = new org.springframework.web.cors.CorsConfiguration();
        config.setAllowedOrigins(
                java.util.Arrays.stream(origins.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .toList());
        config.setAllowedMethods(java.util.List.of("GET", "POST", "PUT", "OPTIONS"));
        config.setAllowedHeaders(java.util.List.of("Authorization", "Content-Type"));
        config.setAllowCredentials(false);
        config.setMaxAge(3600L);
        var source = new org.springframework.web.cors.UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtService jwt,
            TokenStore store,
            SecurityErrors errors,
            org.springframework.web.cors.CorsConfigurationSource corsSource)
            throws Exception {
        var authentication = new JwtAuthenticationFilter(jwt, store);
        // 필터는 @Component/@Bean으로 등록하지 않는다: servlet container와 Security 체인의 이중 실행 방지.
        // 이 구성의 실제 순서(테스트에서 고정 검증):
        // DisableEncodeUrl → WebAsyncManagerIntegration → SecurityContextHolder → HeaderWriter →
        // Cors →
        // JwtException → JwtAuthentication → SecurityContextHolderAwareRequest →
        // AnonymousAuthentication →
        // SessionManagement → ExceptionTranslation → Authorization → DispatcherServlet.
        // UsernamePasswordAuthenticationFilter 자체는 formLogin 비활성화로 없고 그 예약 위치만 사용한다.
        return http.cors(c -> c.configurationSource(corsSource))
                .csrf(c -> c.disable()) // 쿠키 인증 없이 명시적 Authorization 헤더/JSON refresh만 사용.
                .formLogin(c -> c.disable())
                .httpBasic(c -> c.disable())
                .logout(c -> c.disable())
                .requestCache(c -> c.disable())
                .sessionManagement(c -> c.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .securityContext(
                        c -> c.securityContextRepository(new NullSecurityContextRepository()))
                .exceptionHandling(
                        c ->
                                c.authenticationEntryPoint(errors.entryPoint())
                                        .accessDeniedHandler(errors.deniedHandler()))
                .authorizeHttpRequests(
                        a -> {
                            a.dispatcherTypeMatchers(DispatcherType.ASYNC, DispatcherType.ERROR)
                                    .permitAll()
                                    .requestMatchers(
                                            HttpMethod.POST,
                                            "/users/login",
                                            "/users/register",
                                            "/users/check-id",
                                            "/api/admin/login",
                                            "/auth/refresh")
                                    .permitAll()
                                    .requestMatchers(
                                            HttpMethod.GET,
                                            "/api/school/search",
                                            "/api/school/search/openapi")
                                    .permitAll()
                                    .requestMatchers(HttpMethod.POST, "/auth/logout")
                                    .authenticated()
                                    .requestMatchers(
                                            HttpMethod.GET,
                                            "/api/admin/schools",
                                            "/api/admin/*/info",
                                            "/api/admin/notifications")
                                    .access(
                                            AuthorizationManagers.allOf(
                                                    hasRole("ADMIN"), hasAuthority("admin:read")))
                                    .requestMatchers(HttpMethod.POST, "/api/admin/change-password")
                                    .access(
                                            AuthorizationManagers.allOf(
                                                    hasRole("ADMIN"), hasAuthority("admin:write")))
                                    .requestMatchers(HttpMethod.PUT, "/api/admin/*/info")
                                    .access(
                                            AuthorizationManagers.allOf(
                                                    hasRole("ADMIN"), hasAuthority("admin:write")))
                                    .requestMatchers(
                                            HttpMethod.GET,
                                            "/api/devices/*/status",
                                            "/api/device-logs/*")
                                    .access(
                                            AuthorizationManagers.allOf(
                                                    hasRole("ADMIN"), hasAuthority("device:read")))
                                    .requestMatchers(
                                            HttpMethod.POST,
                                            "/api/devices/*/capacity",
                                            "/api/devices/reset-load",
                                            "/api/device-logs",
                                            "/api/device/input")
                                    .access(
                                            AuthorizationManagers.allOf(
                                                    hasRole("ADMIN"), hasAuthority("device:write")))
                                    .requestMatchers(
                                            HttpMethod.GET,
                                            "/api/open/v1/schools",
                                            "/api/open/v1/schools/all",
                                            "/api/open/v1/schools/*/total-count",
                                            "/api/open/v1/schools/*/daily-stats",
                                            "/api/open/v1/schools/*/students-ranking",
                                            "/api/open/v1/users/*/total-count",
                                            "/api/open/v1/users/*/recent-logs")
                                    .access(
                                            AuthorizationManagers.allOf(
                                                    hasAnyRole("USER", "ADMIN"),
                                                    hasAuthority("open:read")))
                                    .requestMatchers(HttpMethod.POST, "/api/open/v1/users/*/reward")
                                    .denyAll() // 클라이언트의 임의 포인트 발급 폐쇄.
                                    .requestMatchers(
                                            HttpMethod.GET,
                                            "/users/ranking",
                                            "/users/lives",
                                            "/api/device/logs/*",
                                            "/api/sse/lives/*")
                                    .access(
                                            AuthorizationManagers.allOf(
                                                    hasRole("USER"), hasAuthority("user:read")))
                                    .requestMatchers(
                                            HttpMethod.POST,
                                            "/users/lives/consume",
                                            "/users/session/start",
                                            "/api/school/verify")
                                    .access(
                                            AuthorizationManagers.allOf(
                                                    hasRole("USER"), hasAuthority("user:write")))
                                    .requestMatchers(
                                            HttpMethod.POST, "/game/submit", "/game/record")
                                    .access(
                                            AuthorizationManagers.allOf(
                                                    hasRole("USER"), hasAuthority("game:play")))
                                    .anyRequest()
                                    .denyAll(); // 새 URL은 검토 전 기본 거부. 가짜 휴대폰/학생 인증도 개방하지 않는다.
                        })
                .addFilterBefore(authentication, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JwtExceptionFilter(errors), JwtAuthenticationFilter.class)
                .build();
    }
}
