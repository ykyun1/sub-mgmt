package com.ktds.subs.notification.dto.request;

import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class FCMTokenRequest {
    private String token;
    private String deviceInfo;
}
