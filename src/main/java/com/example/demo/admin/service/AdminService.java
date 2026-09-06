package com.example.demo.admin.service;

import com.example.demo.admin.dto.AdminInfoResponseDto;
import com.example.demo.admin.dto.AdminInfoUpdateRequestDto;
import com.example.demo.admin.dto.AdminLoginRequestDto;
import com.example.demo.admin.dto.AdminLoginResponseDto;
import com.example.demo.device.entity.DeviceCheckLog;
import com.example.demo.school.entity.SchoolEntity;

import java.util.List;
import java.util.Optional;

public interface AdminService {

    List<SchoolEntity> getSchoolsByAdminRegion(Long adminId);

    boolean changePassword(Long adminId, String currentPassword, String newPassword);

    void updateAdminInfo(AdminInfoUpdateRequestDto dto);

    Optional<AdminInfoResponseDto> getAdminInfo(Long adminId);

    List<DeviceCheckLog> getNotifications(Long adminId);
}
