package com.ktds.subs.notification.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import java.time.LocalDateTime;

@Getter
@AllArgsConstructor
public class TokenRegistrationResponse {
    private String status;
    private String message;
    private LocalDateTime registeredAt;
}
