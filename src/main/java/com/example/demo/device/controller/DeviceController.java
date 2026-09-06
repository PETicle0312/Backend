package com.example.demo.device.controller;

import org.springframework.security.access.prepost.PreAuthorize;

import com.example.demo.device.dto.CapacityRequest;
import com.example.demo.device.dto.DeviceStatusResponse;
import com.example.demo.device.entity.Device;
import com.example.demo.device.repository.DeviceRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Optional;

@RestController
@Slf4j
@RequestMapping("/api/devices")
@RequiredArgsConstructor
public class DeviceController {

    private final DeviceRepository deviceRepository;

    @PostMapping("/{deviceId}/capacity")
    public ResponseEntity<String> updateCapacity(
            @PathVariable Long deviceId,
            @RequestBody DeviceStatusResponse request) {

        Optional<Device> optionalDevice = deviceRepository.findById(deviceId);
        if (optionalDevice.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Device not found");
        }

        Device device = optionalDevice.get();

        // 센서에서 계산된 퍼센트 값으로 capacity 필드 업데이트
        device.setCapacity(request.getCapacity());
        device.setLastUpdate(LocalDateTime.now());

        deviceRepository.save(device);
        return ResponseEntity.ok("Updated");
    }

    @GetMapping("/{deviceId}/status")
    public ResponseEntity<DeviceStatusResponse> getStatus(@PathVariable Long deviceId) {
        return deviceRepository.findById(deviceId)
                .map(device -> ResponseEntity.ok(new DeviceStatusResponse(
                        device.getDeviceId(),
                        device.getCapacity(),
                        device.getLastUpdate()
                )))
                .orElse(ResponseEntity.notFound().build());
    }

    // 수거 완료 시 적재율(%) 0으로 초기화
    @PreAuthorize("#adminId.toString() == authentication.name")
    @PostMapping("/reset-load")
    public ResponseEntity<String> resetLoadRate(
            @RequestParam Long deviceId,
            @RequestParam Long adminId) {

        Optional<Device> optionalDevice = deviceRepository.findById(deviceId);
        if (optionalDevice.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Device not found");
        }

        Device device = optionalDevice.get();
        device.setCapacity(0);
        device.setLastUpdate(LocalDateTime.now());
        deviceRepository.save(device);

        // TODO: 필요 시 로그 테이블에도 저장 가능 (ex: device_check_logs)
        log.info("기기 적재율 초기화를 완료했습니다.");

        return ResponseEntity.ok("Load rate reset to 0%");
    }
}
