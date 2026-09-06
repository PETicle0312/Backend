package com.example.demo.admin.controller;

import com.example.demo.security.TokenRole;

import com.example.demo.security.AuthService;

import org.springframework.security.access.prepost.PreAuthorize;

import com.example.demo.admin.dto.AdminInfoResponseDto;
import com.example.demo.admin.dto.AdminInfoUpdateRequestDto;
import com.example.demo.admin.dto.AdminLoginRequestDto;
import com.example.demo.admin.dto.AdminLoginResponseDto;
import com.example.demo.admin.dto.NotificationResponseDto;
import com.example.demo.admin.dto.SchoolStatusResponse;
import com.example.demo.admin.dto.PasswordChangeRequestDto;
import com.example.demo.admin.service.AdminService;
import com.example.demo.device.entity.Device;
import com.example.demo.device.entity.DeviceCheckLog;
import com.example.demo.device.repository.DeviceRepository;
import com.example.demo.school.entity.SchoolEntity;

import org.springframework.beans.factory.annotation.Autowired;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@Slf4j
@RequestMapping("/api/admin")
public class AdminController {

    private final AdminService adminService;
    private final AuthService authService;

    @Autowired
    private DeviceRepository deviceRepository;

    public AdminController(AdminService adminService, AuthService authService) {
        this.authService = authService;
        this.adminService = adminService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AdminLoginRequestDto dto) {
        log.info("관리자 로그인 요청을 수신했습니다.");

        return ResponseEntity.ok().header("Cache-Control", "no-store").body(
            authService.login(dto.getAdminId() == null ? null : dto.getAdminId().toString(), dto.getPassword(), TokenRole.ADMIN));
    }

    @PreAuthorize("#adminId.toString() == authentication.name")
    @GetMapping("/schools")
    public ResponseEntity<List<SchoolStatusResponse>> getSchoolsByRegion(@RequestParam Long adminId) {
        List<SchoolEntity> schools = adminService.getSchoolsByAdminRegion(adminId);

        List<SchoolStatusResponse> response = schools.stream().map(school -> {
            List<Device> devices = deviceRepository.findBySchool(school);
            Device device = devices.isEmpty() ? null : devices.get(0);

            double loadRate = (device != null) ? device.getCapacity() : 0.0;
            Long deviceId = (device != null) ? device.getDeviceId() : null;

            return new SchoolStatusResponse(
                school.getSchoolName(),
                school.getAddress(),
                loadRate,
                deviceId
            );
        }).toList();

        return ResponseEntity.ok(response);
    }

    @PreAuthorize("#request.adminId != null and #request.adminId.toString() == authentication.name")
    @PostMapping("/change-password")
    public ResponseEntity<String> changePassword(@RequestBody PasswordChangeRequestDto request) {
        boolean result = adminService.changePassword(
            request.getAdminId(),
            request.getCurrentPassword(),
            request.getNewPassword()
        );

        if (result) {
            return ResponseEntity.ok("비밀번호 변경 성공");
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("현재 비밀번호가 일치하지 않습니다.");
        }
    }

    @PreAuthorize("#adminId.toString() == authentication.name")
    @PutMapping("/{adminId}/info")
    public ResponseEntity<String> updateAdminInfo(
            @PathVariable Long adminId,
            @RequestBody AdminInfoUpdateRequestDto dto) {

        dto.setAdminId(adminId);
        adminService.updateAdminInfo(dto);
        return ResponseEntity.ok("관리자 정보가 변경되었습니다.");
    }

    @PreAuthorize("#adminId.toString() == authentication.name")
    @GetMapping("/{adminId}/info")
    public ResponseEntity<AdminInfoResponseDto> getAdminInfo(@PathVariable Long adminId) {
        return adminService.getAdminInfo(adminId)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.status(HttpStatus.NOT_FOUND).build());
    }

    @PreAuthorize("#adminId.toString() == authentication.name")
    @GetMapping("/notifications")
    public ResponseEntity<List<NotificationResponseDto>> getNotifications(@RequestParam Long adminId) {
        log.debug("관리자 알림 조회 요청을 수신했습니다.");

        List<DeviceCheckLog> logs = adminService.getNotifications(adminId);

        List<NotificationResponseDto> response = logs.stream().map(log -> {
            return new NotificationResponseDto(
                log.getCheckLogId(),
                log.getAdminId().getAdmName(),
                log.getActionType(),
                log.getLogTime(),
                log.getDeviceId().getDeviceId(),
                log.getDeviceId().getSchool().getSchoolName()
            );
        }).toList();

        return ResponseEntity.ok(response);
    }
}
