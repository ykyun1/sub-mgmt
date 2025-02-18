package com.ktds.subs.auth.service;

import com.ktds.subs.auth.dto.response.TokenResponse;

public interface AuthService {
    TokenResponse login(String provider, String code);
    TokenResponse refresh(String refreshToken);
    void logout(String refreshToken);
    TokenResponse signup(String provider, String code);
}
