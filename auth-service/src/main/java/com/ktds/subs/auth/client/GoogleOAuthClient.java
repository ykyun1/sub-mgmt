package com.ktds.subs.auth.client;

import com.ktds.subs.auth.dto.GoogleUserInfo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class GoogleOAuthClient {

    private final RestTemplate restTemplate;
    
    @Value("${oauth2.google.token-uri}")
    private String tokenUri;
    
    @Value("${oauth2.google.user-info-uri}")
    private String userInfoUri;

    public GoogleOAuthClient() {
        this.restTemplate = new RestTemplate();
    }

    public GoogleUserInfo getUserInfo(String code) {
        // 1. 인증 코드로 액세스 토큰 요청
        String accessToken = getAccessToken(code);
        
        // 2. 액세스 토큰으로 사용자 정보 요청
        return getUserInfoWithToken(accessToken);
    }

    private String getAccessToken(String code) {
        // OAuth 토큰 요청 로직 구현
        return "access_token";
    }

    private GoogleUserInfo getUserInfoWithToken(String accessToken) {
        // 사용자 정보 요청 로직 구현
        return new GoogleUserInfo();
    }
}
