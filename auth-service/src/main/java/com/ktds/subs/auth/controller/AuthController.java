package com.ktds.subs.auth.controller;

import com.ktds.subs.auth.dto.request.SocialLoginRequest;
import com.ktds.subs.auth.dto.response.TokenResponse;
import com.ktds.subs.auth.service.AuthService;
import com.ktds.subs.common.dto.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@Tag(name = "인증", description = "인증 관련 API")
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    
    private final AuthService authService;
    
    @Operation(summary = "소셜 로그인", description = "소셜 계정으로 로그인합니다.")
    @PostMapping("/login")
    public ApiResponse<TokenResponse> login(@RequestBody SocialLoginRequest request) {
        return ApiResponse.success(authService.login(request.getProvider(), request.getCode()));
    }
}
