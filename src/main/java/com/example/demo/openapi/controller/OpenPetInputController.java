package com.example.demo.openapi.controller;

import org.springframework.security.access.prepost.PreAuthorize;

import com.example.demo.game.service.PointService;
import com.example.demo.openapi.dto.*;
import com.example.demo.openapi.service.OpenPetInputService;
import com.example.demo.user.entity.User;
import com.example.demo.user.repository.UserRepository;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Validated
@RestController
@RequestMapping("/api/open/v1")
@RequiredArgsConstructor
@SecurityRequirement(name = "bearerAuth")
@Tag(name = "Open API - PET 입력")
public class OpenPetInputController {

    private final OpenPetInputService svc;
    private final PointService pointService;
    private final UserRepository userRepository;


    // from이 없으면 전체, 있으면 해당 시점부터 합계
    // format=plain은 숫자만 응답
    @PreAuthorize("hasRole('USER') and #userId == authentication.name")
    @GetMapping("/users/{userId}/total-count")
    public ResponseEntity<?> getUserTotal(
            @PathVariable String userId,
            @RequestParam(required = false) String from,            // ISO-8601: yyyy-MM-dd 또는 yyyy-MM-ddTHH:mm:ss
            @RequestParam(defaultValue = "json") String format      // json | plain
    ) {
        TotalCountDto dto = (from == null || from.isBlank())
                ? svc.getUserTotal(userId)
                : svc.getUserTotalFromDate(userId, parseFlexible(from));

        if ("plain".equalsIgnoreCase(format)) {
            return ResponseEntity.ok()
                    .header("Content-Type", "text/plain; charset=UTF-8")
                    .body(String.valueOf(dto.totalCount()));
        }
        return ResponseEntity.ok(dto);
    }

    @GetMapping("/schools/{schoolId}/total-count")
    public TotalCountDto getSchoolTotal(@PathVariable Long schoolId) {
        return svc.getSchoolTotal(schoolId);
    }

    @PreAuthorize("hasRole('USER') and #userId == authentication.name")
    @GetMapping("/users/{userId}/recent-logs")
    public List<PetLogPublicDto> recentLogs(@PathVariable String userId,
                                            @RequestParam(defaultValue = "20")
                                            @Min(1) @Max(50) int limit) {
        return svc.getUserRecentLogs(userId, limit);
    }

    @PostMapping("/users/{userId}/reward")
    public ResponseEntity<PointResponseDto> rewardForApiCall(
            @PathVariable String userId,
            @RequestParam String uri
    ) {
        int addedPoints = pointService.addPointForApiCall(userId, uri);

        User user = userRepository.findByUserId(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + userId));

        PointResponseDto response = new PointResponseDto(addedPoints, user.getScore());

        return ResponseEntity.ok(response);
    }


    @GetMapping("/schools/{schoolId}/daily-stats")
    public List<DailyStatDto> dailyStats(@PathVariable Long schoolId) {
        return svc.getDailyStatsBySchool(schoolId);
    }

    // format=csv는 앱인벤터에서 파싱하기 쉽게 제공한다.
    @GetMapping("/schools/{schoolId}/students-ranking")
    public ResponseEntity<?> ranking(@PathVariable Long schoolId,
                                     @RequestParam(defaultValue = "json") String format // json | csv
    ) {
        List<StudentsRankingDto> list = svc.getStudentsRanking(schoolId);
        if ("csv".equalsIgnoreCase(format)) {
            StringBuilder sb = new StringBuilder();
            sb.append("userId,name,totalCount\n");
            for (StudentsRankingDto r : list) {
                sb.append(r.userId()).append(",")
                  .append(escapeCsv(r.name())).append(",")
                  .append(r.totalCount()).append("\n");
            }
            return ResponseEntity.ok()
                    .header("Content-Type", "text/csv; charset=UTF-8")
                    .body(sb.toString());
        }
        return ResponseEntity.ok(list);
    }

    private LocalDateTime parseFlexible(String s) {
        try {
            return LocalDateTime.parse(s);
        } catch (Exception ignore) {
            return LocalDate.parse(s).atStartOfDay();
        }
    }

    private static String escapeCsv(String s) {
        if (s == null) return "";
        boolean needQuote = s.contains(",") || s.contains("\"") || s.contains("\n") || s.contains("\r");
        String v = s.replace("\"", "\"\"");
        return needQuote ? "\"" + v + "\"" : v;
    }
}
