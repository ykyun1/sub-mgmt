package com.ktds.subs.auth.service.impl;

import com.ktds.subs.auth.domain.Token;
import com.ktds.subs.auth.domain.User;
import com.ktds.subs.auth.dto.response.TokenResponse;
import com.ktds.subs.auth.repository.TokenRepository;
import com.ktds.subs.auth.repository.UserRepository;
import com.ktds.subs.auth.service.AuthService;
import com.ktds.subs.auth.util.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final GoogleOAuthClient googleOAuthClient;

    @Override
    @Transactional
    public TokenResponse login(String provider, String code) {
        // 구글 OAuth로 사용자 정보 조회
        GoogleUserInfo userInfo = googleOAuthClient.getUserInfo(code);
        
        // 기존 사용자 조회 또는 새로운 사용자 생성
        User user = userRepository.findByProviderAndProviderUserId(provider, userInfo.getId())
            .orElseGet(() -> signup(provider, userInfo));

        // 토큰 생성
        String accessToken = jwtTokenProvider.createAccessToken(user.getUserId());
        String refreshToken = jwtTokenProvider.createRefreshToken();

        // Refresh 토큰 저장
        saveRefreshToken(user.getUserId(), refreshToken);

        return new TokenResponse(accessToken, refreshToken);
    }

    @Override
    @Transactional
    public TokenResponse refresh(String refreshToken) {
        // Refresh 토큰 검증
        Token token = tokenRepository.findByRefreshToken(refreshToken)
            .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        // 새로운 액세스 토큰 발급
        String newAccessToken = jwtTokenProvider.createAccessToken(token.getUserId());

        return new TokenResponse(newAccessToken, refreshToken);
    }

    @Override
    @Transactional
    public void logout(String refreshToken) {
        Token token = tokenRepository.findByRefreshToken(refreshToken)
            .orElseThrow(() -> new RuntimeException("Invalid refresh token"));
        tokenRepository.delete(token);
    }

    private User signup(String provider, GoogleUserInfo userInfo) {
        User user = new User();
        user.setUserId(UUID.randomUUID().toString());
        user.setProvider(provider);
        user.setProviderUserId(userInfo.getId());
        user.setNickname(userInfo.getName());
        return userRepository.save(user);
    }

    private void saveRefreshToken(String userId, String refreshToken) {
        Token token = new Token();
        token.setUserId(userId);
        token.setRefreshToken(refreshToken);
        token.setExpiresAt(LocalDateTime.now().plusDays(14));
        tokenRepository.save(token);
    }
}
