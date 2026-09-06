package com.example.demo.security;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.example.demo.user.entity.User;
import com.example.demo.user.repository.UserRepository;
import com.example.demo.user.service.LifeService;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.net.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;

@SpringBootTest(properties = "security.cors.allowed-origins=https://client.example")
@AutoConfigureMockMvc
class JwtIntegrationTest {
    // 실제 Redis 프로세스 및 실제 Lua를 사용한다. 외부 운영 Redis를 flush하지 않는다.
    static Process redisProcess;
    static int port;

    @DynamicPropertySource
    static void redis(DynamicPropertyRegistry registry) throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        redisProcess =
                new ProcessBuilder(
                                System.getenv().getOrDefault("REDIS_SERVER", "redis-server"),
                                "--bind",
                                "127.0.0.1",
                                "--port",
                                Integer.toString(port),
                                "--save",
                                "",
                                "--appendonly",
                                "no")
                        .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                        .redirectError(ProcessBuilder.Redirect.DISCARD)
                        .start();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (true) {
            try (Socket socket = new Socket("127.0.0.1", port)) {
                break;
            } catch (java.io.IOException e) {
                if (System.nanoTime() > deadline) throw e;
                Thread.sleep(20);
            }
        }
        registry.add("spring.data.redis.port", () -> port);
        registry.add("spring.data.redis.host", () -> "127.0.0.1");
    }

    @AfterAll
    static void stopRedis() throws Exception {
        if (redisProcess != null) {
            redisProcess.destroy();
            redisProcess.waitFor(5, TimeUnit.SECONDS);
        }
    }

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired JwtService jwt;
    @Autowired TokenStore store;
    @Autowired AuthService auth;
    @Autowired StringRedisTemplate redis;
    @Autowired FilterChainProxy chain;
    @MockitoBean UserRepository users;
    @MockitoBean LifeService lives;
    @MockitoBean com.example.demo.admin.repository.AdminRepository admins;
    @MockitoBean com.example.demo.admin.service.AdminService adminService;

    @BeforeEach
    void account() {
        when(users.findByUserId("alice"))
                .thenReturn(
                        Optional.of(
                                User.builder()
                                        .userId("alice")
                                        .password(
                                                new BCryptPasswordEncoder()
                                                        .encode("correct-password"))
                                        .build()));
        when(users.existsByUserId("alice")).thenReturn(true);
        when(lives.currentLives("alice")).thenReturn(3);
    }

    JwtService.Pair login() throws Exception {
        var response =
                mvc.perform(
                                post("/users/login")
                                        .contentType("application/json")
                                        .content(
                                                "{\"userId\":\"alice\",\"password\":\"correct-password\"}"))
                        .andExpect(status().isOk())
                        .andExpect(header().string("Cache-Control", "no-store"))
                        .andReturn();
        return mapper.readValue(response.getResponse().getContentAsString(), JwtService.Pair.class);
    }

    @Test
    void realLoginJwtAndStatelessContext() throws Exception {
        var tokens = login();
        var result =
                mvc.perform(
                                get("/users/lives")
                                        .param("userId", "alice")
                                        .header("Authorization", "Bearer " + tokens.accessToken()))
                        .andExpect(status().isOk())
                        .andExpect(content().string("3"))
                        .andReturn();
        assertNull(result.getRequest().getSession(false));
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        mvc.perform(get("/users/lives").param("userId", "alice"))
                .andExpect(status().isUnauthorized());
        mvc.perform(
                        get("/api/admin/schools")
                                .param("adminId", "1")
                                .header("Authorization", "Bearer " + tokens.accessToken()))
                .andExpect(status().isForbidden());
    }

    @Test
    void rotationReplayRevokesFamily() throws Exception {
        var first = login();
        var response =
                mvc.perform(
                                post("/auth/refresh")
                                        .contentType("application/json")
                                        .content(
                                                mapper.writeValueAsString(
                                                        Map.of(
                                                                "refreshToken",
                                                                first.refreshToken()))))
                        .andExpect(status().isOk())
                        .andReturn();
        var second =
                mapper.readValue(
                        response.getResponse().getContentAsString(), JwtService.Pair.class);
        assertNotEquals(first.refreshToken(), second.refreshToken());
        mvc.perform(
                        post("/auth/refresh")
                                .contentType("application/json")
                                .content(
                                        mapper.writeValueAsString(
                                                Map.of("refreshToken", first.refreshToken()))))
                .andExpect(status().isUnauthorized());
        mvc.perform(
                        get("/users/lives")
                                .param("userId", "alice")
                                .header("Authorization", "Bearer " + second.accessToken()))
                .andExpect(status().isUnauthorized());
        assertThrows(io.jsonwebtoken.JwtException.class, () -> auth.refresh(second.refreshToken()));
    }

    @Test
    void logoutBlacklistsWithRemainingTtlAndRevokesRefresh() throws Exception {
        var tokens = login();
        var id = jwt.parse(tokens.accessToken(), "access");
        mvc.perform(post("/auth/logout").header("Authorization", "Bearer " + tokens.accessToken()))
                .andExpect(status().isNoContent());
        Long ttl =
                redis.getExpire(
                        "auth:{" + id.session() + "}:blacklist:" + id.id(), TimeUnit.MILLISECONDS);
        assertNotNull(ttl);
        assertTrue(ttl > 0 && ttl <= 900000);
        mvc.perform(
                        get("/users/lives")
                                .param("userId", "alice")
                                .header("Authorization", "Bearer " + tokens.accessToken()))
                .andExpect(status().isUnauthorized());
        assertThrows(io.jsonwebtoken.JwtException.class, () -> auth.refresh(tokens.refreshToken()));
    }

    String signed(String secret, Instant expiry, String type, String issuer) {
        return Jwts.builder()
                .subject("alice")
                .issuer(issuer)
                .audience()
                .add("peticle-api")
                .and()
                .id(UUID.randomUUID().toString())
                .claim("sid", UUID.randomUUID().toString())
                .claim("role", "USER")
                .claim("type", type)
                .expiration(Date.from(expiry))
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret)), Jwts.SIG.HS256)
                .compact();
    }

    @Test
    void parsingFailuresBecomeJsonBeforeController() throws Exception {
        String secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        String expired = signed(secret, Instant.now().minusSeconds(60), "access", "peticle");
        mvc.perform(
                        get("/users/lives")
                                .param("userId", "alice")
                                .header("Authorization", "Bearer " + expired))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("TOKEN_EXPIRED"));
        for (String token :
                List.of(
                        "garbage",
                        signed(
                                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=",
                                Instant.now().plusSeconds(60),
                                "access",
                                "peticle"),
                        signed(secret, Instant.now().plusSeconds(60), "refresh", "peticle"),
                        signed(secret, Instant.now().plusSeconds(60), "access", "other"))) {
            mvc.perform(
                            get("/users/lives")
                                    .param("userId", "alice")
                                    .header("Authorization", "Bearer " + token))
                    .andExpect(status().isUnauthorized())
                    .andExpect(content().contentTypeCompatibleWith("application/json"))
                    .andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
        }
        verifyNoInteractions(lives);
    }

    @Test
    void badCredentialsUseSameError() throws Exception {
        mvc.perform(
                        post("/users/login")
                                .contentType("application/json")
                                .content("{\"userId\":\"alice\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }

    @Test
    void concurrentHttpRefreshHasSingleWinnerAndRevokesFamily() throws Exception {
        var tokens = login();
        String body = mapper.writeValueAsString(Map.of("refreshToken", tokens.refreshToken()));
        var pool = Executors.newFixedThreadPool(2);
        var barrier = new CyclicBarrier(2);
        try {
            Callable<Integer> call =
                    () -> {
                        barrier.await();
                        return mvc.perform(
                                        post("/auth/refresh")
                                                .contentType("application/json")
                                                .content(body))
                                .andReturn()
                                .getResponse()
                                .getStatus();
                    };
            var a = pool.submit(call);
            var b = pool.submit(call);
            var statuses =
                    new java.util.HashSet<>(
                            List.of(a.get(5, TimeUnit.SECONDS), b.get(5, TimeUnit.SECONDS)));
            assertEquals(java.util.Set.of(200, 401), statuses);
            var identity = jwt.parse(tokens.accessToken(), "access");
            assertTrue(store.blocked(identity.session(), identity.id()));
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void filterOrderIsExplicit() {
        var names =
                chain.getFilterChains().get(0).getFilters().stream()
                        .map(f -> f.getClass().getSimpleName())
                        .toList();
        assertEquals(
                List.of(
                        "DisableEncodeUrlFilter",
                        "WebAsyncManagerIntegrationFilter",
                        "SecurityContextHolderFilter",
                        "HeaderWriterFilter",
                        "CorsFilter",
                        "JwtExceptionFilter",
                        "JwtAuthenticationFilter",
                        "SecurityContextHolderAwareRequestFilter",
                        "AnonymousAuthenticationFilter",
                        "SessionManagementFilter",
                        "ExceptionTranslationFilter",
                        "AuthorizationFilter"),
                names);
    }

    @Test
    void realAdminLoginAndRoleIsolation() throws Exception {
        when(admins.findByAdminId(1L))
                .thenReturn(
                        Optional.of(
                                com.example.demo.admin.entity.AdminEntity.builder()
                                        .adminId(1L)
                                        .admPassword(
                                                new BCryptPasswordEncoder()
                                                        .encode("admin-password"))
                                        .build()));
        var result =
                mvc.perform(
                                post("/api/admin/login")
                                        .contentType("application/json")
                                        .content("{\"adminId\":1,\"password\":\"admin-password\"}"))
                        .andExpect(status().isOk())
                        .andReturn();
        var tokens =
                mapper.readValue(result.getResponse().getContentAsString(), JwtService.Pair.class);
        mvc.perform(
                        get("/api/admin/schools")
                                .param("adminId", "1")
                                .header("Authorization", "Bearer " + tokens.accessToken()))
                .andExpect(status().isOk());
        verify(adminService).getSchoolsByAdminRegion(1L);
        mvc.perform(
                        get("/users/lives")
                                .param("userId", "alice")
                                .header("Authorization", "Bearer " + tokens.accessToken()))
                .andExpect(status().isForbidden());
    }

    @Test
    void nearExpiryAccessNeverOutlivesSessionAndRotationKeepsDeadline() {
        String sid = UUID.randomUUID().toString();
        Instant deadline =
                Instant.now().plusSeconds(30).truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        var pair = jwt.issue("alice", TokenRole.USER, sid, deadline);
        store.create(sid, AuthService.hash(pair.refreshToken()), deadline);
        long before = redis.getExpire("auth:{" + sid + "}:refresh", TimeUnit.MILLISECONDS);
        var rotated = auth.refresh(pair.refreshToken());
        long after = redis.getExpire("auth:{" + sid + "}:refresh", TimeUnit.MILLISECONDS);
        assertTrue(after > 0 && after <= before);
        assertEquals(deadline, jwt.parse(rotated.accessToken(), "access").expiresAt());
        assertEquals(deadline, jwt.parse(rotated.refreshToken(), "refresh").expiresAt());
        assertEquals(
                AuthService.hash(rotated.refreshToken()),
                redis.opsForValue().get("auth:{" + sid + "}:refresh"));
    }

    @Test
    void missingSessionFailsClosedAndRefreshCannotBeUsedAsAccess() throws Exception {
        var tokens = login();
        var identity = jwt.parse(tokens.accessToken(), "access");
        mvc.perform(
                        get("/users/lives")
                                .param("userId", "alice")
                                .header("Authorization", "Bearer " + tokens.refreshToken()))
                .andExpect(status().isUnauthorized());
        assertThrows(io.jsonwebtoken.JwtException.class, () -> auth.refresh(tokens.accessToken()));
        redis.delete("auth:{" + identity.session() + "}:refresh");
        mvc.perform(
                        get("/users/lives")
                                .param("userId", "alice")
                                .header("Authorization", "Bearer " + tokens.accessToken()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void ownershipChecksProtectActualGameAndOpenControllers() throws Exception {
        var tokens = login();
        String bearer = "Bearer " + tokens.accessToken();
        mvc.perform(
                        post("/game/submit")
                                .header("Authorization", bearer)
                                .contentType("application/json")
                                .content("{\"userId\":\"bob\",\"score\":100}"))
                .andExpect(status().isForbidden());
        mvc.perform(
                        post("/game/record")
                                .header("Authorization", bearer)
                                .param("userId", "bob")
                                .param("score", "10")
                                .param("playTimeSec", "1"))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/open/v1/users/bob/recent-logs").header("Authorization", bearer))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/device/logs/bob").header("Authorization", bearer))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/sse/lives/bob").header("Authorization", bearer))
                .andExpect(status().isForbidden());
    }

    @Test
    void duplicateOrEmptyAuthorizationRejected() throws Exception {
        var tokens = login();
        mvc.perform(
                        get("/users/lives")
                                .param("userId", "alice")
                                .header(
                                        "Authorization",
                                        "Bearer " + tokens.accessToken(),
                                        "Bearer other"))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/users/lives").param("userId", "alice").header("Authorization", "Bearer "))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void corsPreflightRunsBeforeJwtAndAuthorization() throws Exception {
        mvc.perform(
                        options("/users/lives")
                                .header("Origin", "https://client.example")
                                .header("Access-Control-Request-Method", "GET")
                                .header("Access-Control-Request-Headers", "authorization"))
                .andExpect(status().isOk())
                .andExpect(
                        header().string("Access-Control-Allow-Origin", "https://client.example"));
    }

    @Test
    void plaintextAdminCredentialIsNeverAccepted() throws Exception {
        when(admins.findByAdminId(1L))
                .thenReturn(
                        Optional.of(
                                com.example.demo.admin.entity.AdminEntity.builder()
                                        .adminId(1L)
                                        .admPassword("legacy-plaintext")
                                        .build()));
        mvc.perform(
                        post("/api/admin/login")
                                .contentType("application/json")
                                .content("{\"adminId\":1,\"password\":\"legacy-plaintext\"}"))
                .andExpect(status().isUnauthorized());
    }
}
