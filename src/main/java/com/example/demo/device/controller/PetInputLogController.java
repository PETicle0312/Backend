package com.example.demo.device.controller;

import org.springframework.security.access.prepost.PreAuthorize;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import lombok.RequiredArgsConstructor;
import com.example.demo.device.dto.PetInputLogDto;
import com.example.demo.device.dto.PetInputResult;
import com.example.demo.device.service.PetInputLogService;

@RestController
@RequestMapping("/api/device")
@RequiredArgsConstructor
public class PetInputLogController {

    private final PetInputLogService petInputLogService;

    @PostMapping("/input")
    public ResponseEntity<?> inputPet(@RequestBody PetInputLogDto dto) {
        try {
            PetInputResult result = petInputLogService.saveInputLog(dto);
            return ResponseEntity.ok(result);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(e.getMessage());
        }
    }

    @PreAuthorize("#userId == authentication.name")
    @GetMapping("/logs/{userId}")
    public ResponseEntity<List<PetInputLogDto>> getUserLogs(@PathVariable String userId) {
        List<PetInputLogDto> logs = petInputLogService.getLogsByUserId(userId);
        return ResponseEntity.ok(logs);
    }
}
