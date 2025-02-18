package com.ktds.subs.auth.dto.response;

import com.ktds.subs.auth.domain.User;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class NotificationSettingResponse {
    private boolean enabled;

    public static NotificationSettingResponse from(User user) {
        return NotificationSettingResponse.builder()
            .enabled(user.isNotificationEnabled())
            .build();
    }
}
