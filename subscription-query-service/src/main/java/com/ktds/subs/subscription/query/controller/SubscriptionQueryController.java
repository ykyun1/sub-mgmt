package com.ktds.subs.subscription.query.controller;

import com.ktds.subs.common.dto.ApiResponse;
import com.ktds.subs.subscription.query.service.SubscriptionQueryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@Tag(name = "구독 조회", description = "구독 서비스 Query API")
@RestController
@RequestMapping("/api/subscriptions")
@RequiredArgsConstructor
public class SubscriptionQueryController {

    private final SubscriptionQueryService subscriptionQueryService;

    @Operation(summary = "구독 대시보드 조회", description = "사용자의 구독 서비스 요약 정보를 조회합니다.")
    @GetMapping("/summary")
    public ApiResponse<?> getDashboard(
            @RequestHeader("X-User-ID") String userId) {
        return ApiResponse.success(subscriptionQueryService.getDashboard(userId));
    }

    @Operation(summary = "카테고리별 구독 조회", description = "카테고리별 구독 서비스 목록을 조회합니다.")
    @GetMapping("/category")
    public ApiResponse<?> getSubscriptionsByCategory(
            @RequestHeader("X-User-ID") String userId,
            @RequestParam String category) {
        return ApiResponse.success(subscriptionQueryService.getSubscriptionsByCategory(userId, category));
    }

    @Operation(summary = "월별 결제일 조회", description = "특정 월의 결제 일정을 조회합니다.")
    @GetMapping("/calendar")
    public ApiResponse<?> getPaymentSchedule(
            @RequestHeader("X-User-ID") String userId,
            @RequestParam String yearMonth) {
        return ApiResponse.success(subscriptionQueryService.getPaymentSchedule(userId, yearMonth));
    }

    @Operation(summary = "월별 총액 조회", description = "특정 월의 총 결제 금액을 조회합니다.")
    @GetMapping("/total")
    public ApiResponse<?> getTotalAmount(
            @RequestHeader("X-User-ID") String userId,
            @RequestParam String yearMonth) {
        return ApiResponse.success(subscriptionQueryService.getTotalAmount(userId, yearMonth));
    }
}
