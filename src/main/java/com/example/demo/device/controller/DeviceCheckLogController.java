package com.example.demo.device.controller;

import org.springframework.security.access.prepost.PreAuthorize;

import com.example.demo.admin.entity.AdminEntity;
import com.example.demo.admin.repository.AdminRepository;
import com.example.demo.device.dto.DeviceCheckLogDto;
import com.example.demo.device.entity.Device;
import com.example.demo.device.entity.DeviceCheckLog;
import com.example.demo.device.repository.DeviceCheckLogRepository;
import com.example.demo.device.repository.DeviceRepository;
import com.example.demo.device.service.DeviceCheckLogService;
import lombok.RequiredArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api/device-logs")
@RequiredArgsConstructor
public class DeviceCheckLogController {

    private final DeviceCheckLogRepository logRepository;
    private final AdminRepository adminRepository;
    private final DeviceRepository deviceRepository;
    private final DeviceCheckLogService deviceCheckLogService;

    /**
     * 관리자 작업 이력 저장 (수거/점검/수리 등)
     * POST /api/device-logs
     */
    @PreAuthorize("#request.adminId != null and #request.adminId.toString() == authentication.name")
    @PostMapping
    public ResponseEntity<?> logAction(@RequestBody LogRequest request) {
        AdminEntity admin = adminRepository.findById(request.getAdminId())
                .orElseThrow(() -> new IllegalArgumentException("Invalid adminId"));
        Device device = deviceRepository.findById(request.getDeviceId())
                .orElseThrow(() -> new IllegalArgumentException("Invalid deviceId"));

        DeviceCheckLog log = DeviceCheckLog.builder()
                .deviceId(device)
                .adminId(admin)
                .actionType(request.getActionType())
                .logTime(LocalDateTime.now())
                .build();

        logRepository.save(log);

        return ResponseEntity.ok().body("{\"message\":\"Logged\"}");
    }

    /**
     * 특정 기기의 '월별' 수거내역 조회
     * GET /api/device-logs/{deviceId}?yearMonth=2025-08
     */
    @GetMapping("/{deviceId}")
    public ResponseEntity<List<DeviceCheckLogDto>> getCheckLogsByDevice(
            @PathVariable Long deviceId,
            @RequestParam String yearMonth // yyyy-MM
    ) {
        if (!Pattern.matches("\\d{4}-\\d{2}", yearMonth)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        List<DeviceCheckLogDto> logs =
                deviceCheckLogService.getLogsByDeviceAndMonth(deviceId, yearMonth);
        return ResponseEntity.ok(logs);
    }

    @Getter
    @Setter
    public static class LogRequest {
        private Long adminId;     // 관리자 번호
        private Long deviceId;    // 디바이스 번호
        private String actionType; // "수거", "점검", "수리" 등
    }
}
