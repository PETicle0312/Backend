package com.example.demo.user.controller;

import com.example.demo.security.TokenRole;

import com.example.demo.security.JwtService;

import com.example.demo.security.AuthService;

import org.springframework.security.access.prepost.PreAuthorize;

import com.example.demo.user.dto.*;
import com.example.demo.user.service.UserService;
import com.example.demo.user.service.LifeService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final LifeService lifeService;
    private final AuthService authService;

    // 회원가입
    @PostMapping("/register")
    public String registerUser(@RequestBody UserRegisterDto dto) {
        if (dto == null) {
            log.warn("회원가입 요청 DTO가 null입니다.");
            return "입력된 데이터가 잘못되었습니다.";
        }
        log.info("회원가입 요청을 수신했습니다.");
        return userService.registerUser(dto);
    }

    // 로그인
    @PostMapping("/login")
    public ResponseEntity<JwtService.Pair> login(@RequestBody LoginRequestDto dto) {
        log.debug("로그인 요청을 수신했습니다.");
        return ResponseEntity.ok().header("Cache-Control", "no-store").body(authService.login(dto.getUserId(), dto.getPassword(), TokenRole.USER));
    }

    // 랭킹
    @GetMapping("/ranking")
    public ResponseEntity<List<UserRankingDto>> getRanking() {
        return ResponseEntity.ok(userService.getUserRanking());
    }

    // 게임 세션 시작
    @PreAuthorize("#dto.userId == authentication.name")
    @PostMapping("/session/start")
    public ResponseEntity<String> startSession(@RequestBody StartSessionDto dto) {
        userService.startGameSession(dto);
        return ResponseEntity.ok("게임 세션 시작됨");
    }

    // 휴대폰 인증
    @PostMapping("/verify-phone")
    public ResponseEntity<String> verifyPhoneNumber(@RequestBody PhoneVerifyDto dto) {
        String phone = dto.getPhoneNumber();
        if (phone == null || !phone.matches("^010\\d{7,8}$")) {
            return ResponseEntity.badRequest().body("유효하지 않은 휴대폰 번호 형식입니다.");
        }
        return ResponseEntity.ok("휴대폰 번호 인증 성공");
    }

    // 아이디 중복 확인
    @PostMapping("/check-id")
    public ResponseEntity<?> checkId(@RequestBody Map<String, String> body) {
        String userId = body.get("userId");
        if (userId == null || userId.isBlank()) {
            return ResponseEntity.badRequest().body("userId 누락됨");
        }
        boolean exists = userService.checkUserIdDuplicate(userId);
        if (exists) {
            return ResponseEntity.ok("이미 존재하는 아이디입니다.");
        } else {
            return ResponseEntity.ok("사용 가능한 아이디입니다.");
        }
    }

    // 학번 인증 없이 저장
    @GetMapping("/check-student")
    public ResponseEntity<String> checkStudent(@RequestParam String studentNumber) {
        return ResponseEntity.ok("재활용을 시작합니다");
    }

    // 현재 하트 조회
    @PreAuthorize("#userId == authentication.name")
    @GetMapping("/lives")
    public ResponseEntity<Integer> getLives(@RequestParam String userId) {
        return ResponseEntity.ok(lifeService.currentLives(userId));
    }

    // 하트 차감
    @PreAuthorize("#userId == authentication.name")
    @PostMapping("/lives/consume")
    public ResponseEntity<Integer> consumeLife(@RequestParam String userId) {
        try {
            int remaining = lifeService.consumeOne(userId);
            return ResponseEntity.ok(remaining);
        } catch (IllegalStateException e) {
            if ("NO_LIFE".equals(e.getMessage())) {
                return ResponseEntity.status(HttpStatus.CONFLICT).body(0); // 하트 없음 → 409
            }
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(-1);
        }
    }
}
