package com.example.demo.security;

import io.jsonwebtoken.JwtException;

import jakarta.servlet.*;
import jakarta.servlet.http.*;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwt;
    private final TokenStore store;

    public JwtAuthenticationFilter(JwtService jwt, TokenStore store) {
        this.jwt = jwt;
        this.store = store;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        String header = req.getHeader("Authorization");
        if (header != null) {
            if (java.util.Collections.list(req.getHeaders("Authorization")).size() != 1
                    || !header.regionMatches(true, 0, "Bearer ", 0, 7)
                    || header.length() > 8192) throw new JwtException("Invalid bearer header");
            var identity = jwt.parse(header.substring(7), "access");
            if (store.blocked(identity.session(), identity.id()))
                throw new JwtException("Revoked token");
            var auth =
                    UsernamePasswordAuthenticationToken.authenticated(
                            identity.subject(),
                            null,
                            identity.role().authorities().stream()
                                    .map(SimpleGrantedAuthority::new)
                                    .toList());
            auth.setDetails(identity);
            // 서명/issuer/audience/type/만료/폐기 검증 후에만 authenticated=true 객체 생성.
            // 새 SecurityContext에 Authentication을 넣고 ThreadLocal 전략의 Holder에 바인딩한다.
            // 같은 요청의 AuthorizationFilter/메서드 보안/컨트롤러가 이를 참조한다.
            // NullSecurityContextRepository이므로 세션에 save하지 않는다. 다음 요청은 JWT를 재검증한다.
            // 외곽 SecurityContextHolderFilter가 finally에서 Holder를 비워 스레드 풀의 사용자 누출을 막는다.
            var context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(auth);
            SecurityContextHolder.setContext(context);
        }
        chain.doFilter(req, res);
    }
}
