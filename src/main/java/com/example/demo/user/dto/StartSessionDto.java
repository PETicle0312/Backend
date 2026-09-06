package com.example.demo.user.dto;

import lombok.Data;
import java.time.LocalDateTime;

@Data
public class StartSessionDto {
    private String userId;
    private String sessionId;
    private LocalDateTime startTime;
}
