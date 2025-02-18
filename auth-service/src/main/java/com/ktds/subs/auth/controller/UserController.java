package com.ktds.subs.auth.controller;

import com.ktds.subs.auth.service.UserService;
import com.ktds.subs.common.dto.ApiResponse;
import com.ktds.subs.auth.dto.request.UserProfileRequest;
import com.ktds.subs.auth.dto.request.NotificationSettingRequest;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@Tag(name = "사용자", description = "사용자 관련 API")
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @Operation(summary = "프로필 조회", description = "사용자 프로필을 조회합니다.")
    @GetMapping("/{userId}")
    public ApiResponse<?> getProfile(@PathVariable String userId) {
        return ApiResponse.success(userService.getProfile(userId));
    }

    @Operation(summary = "프로필 수정", description = "사용자 프로필을 수정합니다.")
    @PutMapping("/{userId}")
    public ApiResponse<?> updateProfile(
            @PathVariable String userId,
            @RequestBody UserProfileRequest request) {
        return ApiResponse.success(userService.updateProfile(userId, request));
    }

    @Operation(summary = "알림 설정 조회", description = "사용자의 알림 설정을 조회합니다.")
    @GetMapping("/{userId}/notifications")
    public ApiResponse<?> getNotificationSettings(@PathVariable String userId) {
        return ApiResponse.success(userService.getNotificationSettings(userId));
    }

    @Operation(summary = "알림 설정 수정", description = "사용자의 알림 설정을 수정합니다.")
    @PutMapping("/{userId}/notifications")
    public ApiResponse<?> updateNotificationSettings(
            @PathVariable String userId,
            @RequestBody NotificationSettingRequest request) {
        return ApiResponse.success(userService.updateNotificationSettings(userId, request));
    }
}
