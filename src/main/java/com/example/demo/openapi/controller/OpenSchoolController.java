package com.example.demo.openapi.controller;

import com.example.demo.openapi.dto.SchoolSimpleDto;
import com.example.demo.openapi.service.OpenSchoolService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.RequiredArgsConstructor;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Validated
@RestController
@RequestMapping("/api/open/v1")
@RequiredArgsConstructor
@SecurityRequirement(name = "bearerAuth")
@Tag(name = "Open API - 학교 검색")
public class OpenSchoolController {

    private final OpenSchoolService svc;

    @Operation(summary = "학교 리스트 검색(페이징)",
            description = "query(이름 부분일치), region, adminRegion으로 필터. 아무것도 없으면 전체 페이징")
    @GetMapping("/schools")
    public Page<SchoolSimpleDto> searchSchools(
            @RequestParam(required = false) String query,
            @RequestParam(required = false) String region,
            @RequestParam(required = false) String adminRegion,
            @ParameterObject Pageable pageable
    ) {
        return svc.search(query, region, adminRegion, pageable);
    }

    @Operation(summary = "학교 리스트 전체(일괄 반환)",
            description = "limit 상한 내에서 전체 또는 조건에 맞는 결과를 한 번에 반환")
    @GetMapping("/schools/all")
    public ResponseEntity<?> searchSchoolsAll(
            @RequestParam(required = false) String query,
            @RequestParam(required = false) String region,
            @RequestParam(required = false) String adminRegion,
            @RequestParam(defaultValue = "500") @Min(1) @Max(2000) int limit,
            @RequestParam(defaultValue = "json") String format // json | csv
    ) {
        List<SchoolSimpleDto> list = svc.searchAll(query, region, adminRegion, limit);

        if ("csv".equalsIgnoreCase(format)) {
            StringBuilder sb = new StringBuilder();
            sb.append("id,name\n");
        for (SchoolSimpleDto s : list) {
            sb.append(s.getId()).append(",")
              .append(escapeCsv(s.getName())).append("\n");
        }
        return ResponseEntity.ok()
                .header("Content-Type", "text/csv; charset=UTF-8")
                .body(sb.toString());
    }

    return ResponseEntity.ok(list);
}

private static String escapeCsv(String s) {
    if (s == null) return "";
    boolean needQuote = s.contains(",") || s.contains("\"") || s.contains("\n") || s.contains("\r");
    String v = s.replace("\"", "\"\"");
    return needQuote ? "\"" + v + "\"" : v;
} }
