package com.ktds.subs.subscription.command.controller;

import com.ktds.subs.common.dto.ApiResponse;
import com.ktds.subs.subscription.command.dto.request.SubscriptionCreateRequest;
import com.ktds.subs.subscription.command.dto.request.SubscriptionUpdateRequest;
import com.ktds.subs.subscription.command.service.SubscriptionCommandService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@Tag(name = "구독 관리", description = "구독 서비스 Command API")
@RestController
@RequestMapping("/api/subscriptions")
@RequiredArgsConstructor
public class SubscriptionCommandController {

    private final SubscriptionCommandService subscriptionCommandService;

    @Operation(summary = "구독 서비스 등록", description = "새로운 구독 서비스를 등록합니다.")
    @PostMapping
    public ApiResponse<?> createSubscription(
            @RequestHeader("X-User-ID") String userId,
            @RequestBody SubscriptionCreateRequest request) {
        return ApiResponse.success(subscriptionCommandService.createSubscription(userId, request));
    }

    @Operation(summary = "구독 서비스 수정", description = "기존 구독 서비스 정보를 수정합니다.")
    @PutMapping("/{subscriptionId}")
    public ApiResponse<?> updateSubscription(
            @RequestHeader("X-User-ID") String userId,
            @PathVariable Long subscriptionId,
            @RequestBody SubscriptionUpdateRequest request) {
        return ApiResponse.success(subscriptionCommandService.updateSubscription(userId, subscriptionId, request));
    }

    @Operation(summary = "구독 서비스 삭제", description = "구독 서비스를 삭제합니다.")
    @DeleteMapping("/{subscriptionId}")
    public ApiResponse<?> deleteSubscription(
            @RequestHeader("X-User-ID") String userId,
            @PathVariable Long subscriptionId) {
        return ApiResponse.success(subscriptionCommandService.deleteSubscription(userId, subscriptionId));
    }
}
