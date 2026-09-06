package com.example.demo.common.sse;

import org.springframework.security.access.prepost.PreAuthorize;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@RestController
@Slf4j
@RequiredArgsConstructor
@RequestMapping("/api/sse")
public class LivesSseController {

    private final LivesSseManager sse;

    @PreAuthorize("#userId == authentication.name")
    @GetMapping(value = "/lives/{userId}", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter subscribe(@PathVariable String userId) {
        log.debug("SSE 구독 요청을 수신했습니다.");
        return sse.subscribe(userId);
    }
}
