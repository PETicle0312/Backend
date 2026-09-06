package com.example.demo.admin.service;

import com.example.demo.admin.dto.AdminInfoResponseDto;
import com.example.demo.admin.dto.AdminInfoUpdateRequestDto;
import com.example.demo.admin.dto.AdminLoginRequestDto;
import com.example.demo.admin.dto.AdminLoginResponseDto;
import com.example.demo.admin.entity.AdminEntity;
import com.example.demo.admin.repository.AdminRepository;
import com.example.demo.device.entity.DeviceCheckLog;
import com.example.demo.device.repository.DeviceCheckLogRepository;
import com.example.demo.school.entity.SchoolEntity;
import com.example.demo.school.repository.SchoolRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AdminServiceImpl implements AdminService {

    private final AdminRepository adminRepository;
    private final SchoolRepository schoolRepository;
    private final DeviceCheckLogRepository deviceCheckLogRepository;

    @Override
    public List<SchoolEntity> getSchoolsByAdminRegion(Long adminId) {
        AdminEntity admin = adminRepository.findByAdminId(adminId)
                .orElseThrow(() -> new IllegalArgumentException("❌ 해당 관리자 ID를 찾을 수 없습니다: " + adminId));

        String adminRegion = admin.getAdminRegion();
        return schoolRepository.findByAdminRegion(adminRegion);
    }

    @Override
    @Transactional
    public boolean changePassword(Long adminId, String currentPassword, String newPassword) {
        AdminEntity admin = adminRepository.findByAdminId(adminId)
                .orElseThrow(() -> new RuntimeException("❌ 해당 관리자를 찾을 수 없습니다."));

        if (currentPassword == null || newPassword == null || newPassword.isBlank()
                || newPassword.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 72
                || !new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder().matches(currentPassword, admin.getAdmPassword())) {
            return false;
        }

        admin.setAdmPassword(new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder(12).encode(newPassword));
        adminRepository.save(admin);
        return true;
    }

    @Override
    @Transactional
    public void updateAdminInfo(AdminInfoUpdateRequestDto dto) {
        AdminEntity admin = adminRepository.findByAdminId(dto.getAdminId())
                .orElseThrow(() -> new IllegalArgumentException("❌ 해당 관리자 없음: " + dto.getAdminId()));

        if (dto.getName() != null) {
            admin.setAdmName(dto.getName());
        }
        if (dto.getRegion() != null) {
            admin.setAdminRegion(dto.getRegion());
        }

        adminRepository.save(admin);
    }

    @Override
    public Optional<AdminInfoResponseDto> getAdminInfo(Long adminId) {
        return adminRepository.findByAdminId(adminId)
                .map(admin -> new AdminInfoResponseDto(
                        admin.getAdminId(),
                        admin.getAdminRegion(),
                        admin.getAdmName()
                ));
    }

    @Override
    public List<DeviceCheckLog> getNotifications(Long adminId) {
        return deviceCheckLogRepository.findByAdminId_AdminIdOrderByLogTimeDesc(adminId);
    }
}
