package com.ktds.subs.notification.controller;

import com.ktds.subs.common.dto.ApiResponse;
import com.ktds.subs.notification.dto.request.FCMTokenRequest;
import com.ktds.subs.notification.service.NotificationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@Tag(name = "알림", description = "알림 관련 API")
@RestController
@RequestMapping("/api/notifications")
@RequiredArgsConstructor
public class NotificationController {

    private final NotificationService notificationService;

    @Operation(summary = "FCM 토큰 등록", description = "사용자의 FCM 토큰을 등록합니다.")
    @PostMapping("/token")
    public ApiResponse<?> registerToken(
            @RequestHeader("X-User-ID") String userId,
            @RequestBody FCMTokenRequest request) {
        return ApiResponse.success(notificationService.registerToken(userId, request));
    }
}
