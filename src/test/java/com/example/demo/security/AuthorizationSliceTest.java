package com.example.demo.security;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.example.demo.admin.controller.AdminController;
import com.example.demo.admin.service.AdminService;
import com.example.demo.device.repository.DeviceRepository;
import com.example.demo.user.controller.UserController;
import com.example.demo.user.service.*;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest({UserController.class, AdminController.class})
@Import({SecurityConfig.class, SecurityErrors.class})
class AuthorizationSliceTest {
    @Autowired MockMvc mvc;
    @MockitoBean UserService users;
    @MockitoBean LifeService lives;
    @MockitoBean AdminService admins;
    @MockitoBean DeviceRepository devices;
    @MockitoBean AuthService auth;
    @MockitoBean JwtService jwt;
    @MockitoBean TokenStore store;

    @Test
    void anonymousCannotRead() throws Exception {
        mvc.perform(get("/users/lives").param("userId", "alice"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
        verifyNoInteractions(lives);
    }

    @Test
    void spoofedHeaderDoesNotAuthenticate() throws Exception {
        mvc.perform(get("/users/lives").param("userId", "alice").header("x-user-id", "alice"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(
            username = "alice",
            authorities = {"ROLE_USER", "user:read"})
    void ownerCanRead() throws Exception {
        when(lives.currentLives("alice")).thenReturn(3);
        mvc.perform(get("/users/lives").param("userId", "alice"))
                .andExpect(status().isOk())
                .andExpect(content().string("3"));
    }

    @Test
    @WithMockUser(
            username = "alice",
            authorities = {"ROLE_USER", "user:read"})
    void otherOwnerForbidden() throws Exception {
        mvc.perform(get("/users/lives").param("userId", "bob"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ACCESS_DENIED"));
        verifyNoInteractions(lives);
    }

    @Test
    @WithMockUser(username = "alice", roles = "USER")
    void roleAloneIsInsufficient() throws Exception {
        mvc.perform(get("/users/lives").param("userId", "alice")).andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "alice", authorities = "user:read")
    void authorityAloneIsInsufficient() throws Exception {
        mvc.perform(get("/users/lives").param("userId", "alice")).andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(
            username = "alice",
            authorities = {"ROLE_USER", "user:read"})
    void readDoesNotAllowWrite() throws Exception {
        mvc.perform(post("/users/lives/consume").param("userId", "alice"))
                .andExpect(status().isForbidden());
        verifyNoInteractions(lives);
    }

    @Test
    @WithMockUser(
            username = "alice",
            authorities = {"ROLE_USER", "user:write"})
    void writeAllowed() throws Exception {
        mvc.perform(post("/users/lives/consume").param("userId", "alice"))
                .andExpect(status().isOk());
        verify(lives).consumeOne("alice");
    }

    @Test
    @WithMockUser(
            username = "alice",
            authorities = {"ROLE_USER", "admin:read"})
    void userCannotBecomeAdminViaAuthority() throws Exception {
        mvc.perform(get("/api/admin/schools").param("adminId", "1"))
                .andExpect(status().isForbidden());
        verifyNoInteractions(admins);
    }

    @Test
    @WithMockUser(
            username = "1",
            authorities = {"ROLE_ADMIN", "admin:read"})
    void adminCanReadOwnRegion() throws Exception {
        mvc.perform(get("/api/admin/schools").param("adminId", "1")).andExpect(status().isOk());
        verify(admins).getSchoolsByAdminRegion(1L);
    }

    @Test
    @WithMockUser(
            username = "1",
            authorities = {"ROLE_ADMIN", "admin:read"})
    void adminCannotImpersonateOtherAdmin() throws Exception {
        mvc.perform(get("/api/admin/schools").param("adminId", "2"))
                .andExpect(status().isForbidden());
        verifyNoInteractions(admins);
    }

    @Test
    @WithMockUser(
            username = "1",
            authorities = {"ROLE_ADMIN", "admin:read"})
    void adminReadCannotWrite() throws Exception {
        mvc.perform(put("/api/admin/1/info").contentType("application/json").content("{}"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(
            username = "1",
            authorities = {"ROLE_ADMIN", "admin:write"})
    void adminWriteAllowed() throws Exception {
        mvc.perform(put("/api/admin/1/info").contentType("application/json").content("{}"))
                .andExpect(status().isOk());
        verify(admins).updateAdminInfo(any());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void unlistedRouteDenied() throws Exception {
        mvc.perform(get("/future/admin-feature")).andExpect(status().isForbidden());
    }

    @Test
    void publicCheckIdAllowed() throws Exception {
        mvc.perform(
                        post("/users/check-id")
                                .contentType("application/json")
                                .content("{\"userId\":\"alice\"}"))
                .andExpect(status().isOk());
    }

    // URL 정책은 컨트롤러 실행 전 결정된다. 각 보호 경로를 익명/역할 누락/권한 누락으로 검증.
    static java.util.stream.Stream<org.junit.jupiter.params.provider.Arguments> protectedRoutes() {
        return java.util.stream.Stream.of(
                org.junit.jupiter.params.provider.Arguments.of(
                        "POST", "/game/submit", "ROLE_USER", "game:play"),
                org.junit.jupiter.params.provider.Arguments.of(
                        "POST", "/game/record", "ROLE_USER", "game:play"),
                org.junit.jupiter.params.provider.Arguments.of(
                        "POST", "/users/session/start", "ROLE_USER", "user:write"),
                org.junit.jupiter.params.provider.Arguments.of(
                        "POST", "/api/school/verify", "ROLE_USER", "user:write"),
                org.junit.jupiter.params.provider.Arguments.of(
                        "GET", "/api/device/logs/alice", "ROLE_USER", "user:read"),
                org.junit.jupiter.params.provider.Arguments.of(
                        "GET", "/api/sse/lives/alice", "ROLE_USER", "user:read"),
                org.junit.jupiter.params.provider.Arguments.of(
                        "GET", "/api/devices/1/status", "ROLE_ADMIN", "device:read"),
                org.junit.jupiter.params.provider.Arguments.of(
                        "GET", "/api/device-logs/1", "ROLE_ADMIN", "device:read"),
                org.junit.jupiter.params.provider.Arguments.of(
                        "POST", "/api/devices/1/capacity", "ROLE_ADMIN", "device:write"),
                org.junit.jupiter.params.provider.Arguments.of(
                        "POST", "/api/devices/reset-load", "ROLE_ADMIN", "device:write"),
                org.junit.jupiter.params.provider.Arguments.of(
                        "POST", "/api/device-logs", "ROLE_ADMIN", "device:write"),
                org.junit.jupiter.params.provider.Arguments.of(
                        "POST", "/api/device/input", "ROLE_ADMIN", "device:write"),
                org.junit.jupiter.params.provider.Arguments.of(
                        "GET", "/api/open/v1/schools", "ROLE_USER", "open:read"),
                org.junit.jupiter.params.provider.Arguments.of(
                        "GET",
                        "/api/open/v1/schools/1/students-ranking",
                        "ROLE_USER",
                        "open:read"));
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.MethodSource("protectedRoutes")
    void protectedRouteRequiresBothRoleAndAuthority(
            String method, String path, String role, String authority) throws Exception {
        mvc.perform(request(org.springframework.http.HttpMethod.valueOf(method), path))
                .andExpect(status().isUnauthorized());
        for (String missing : java.util.List.of(role, authority)) {
            mvc.perform(
                            request(org.springframework.http.HttpMethod.valueOf(method), path)
                                    .with(
                                            org.springframework.security.test.web.servlet.request
                                                    .SecurityMockMvcRequestPostProcessors.user(
                                                            "alice")
                                                    .authorities(
                                                            new org.springframework.security.core
                                                                    .authority
                                                                    .SimpleGrantedAuthority(
                                                                    missing))))
                    .andExpect(status().isForbidden());
        }
    }

    @Test
    @WithMockUser(authorities = {"ROLE_ADMIN", "admin:write", "open:read"})
    void arbitraryRewardsAndFakeVerificationStayClosed() throws Exception {
        mvc.perform(post("/api/open/v1/users/alice/reward")).andExpect(status().isForbidden());
        mvc.perform(post("/users/verify-phone")).andExpect(status().isForbidden());
        mvc.perform(get("/users/check-student")).andExpect(status().isForbidden());
    }

    @Test
    void redisFailureIsJson503AndDoesNotReachController() throws Exception {
        var identity =
                new JwtService.Identity(
                        "alice",
                        TokenRole.USER,
                        "session",
                        "id",
                        java.time.Instant.now().plusSeconds(60));
        when(jwt.parse("token", "access")).thenReturn(identity);
        when(store.blocked("session", "id"))
                .thenThrow(
                        new org.springframework.data.redis.RedisConnectionFailureException(
                                "private infrastructure detail"));
        mvc.perform(
                        get("/users/lives")
                                .param("userId", "alice")
                                .header("Authorization", "Bearer token"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.code").value("AUTH_STORE_UNAVAILABLE"))
                .andExpect(
                        content()
                                .string(
                                        org.hamcrest.Matchers.not(
                                                org.hamcrest.Matchers.containsString(
                                                        "private infrastructure"))));
        verifyNoInteractions(lives);
    }
}
