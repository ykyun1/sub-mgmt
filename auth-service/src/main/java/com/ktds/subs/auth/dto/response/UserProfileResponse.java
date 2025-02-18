package com.ktds.subs.auth.dto.response;

import com.ktds.subs.auth.domain.User;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class UserProfileResponse {
    private String userId;
    private String nickname;
    private String gender;

    public static UserProfileResponse from(User user) {
        return UserProfileResponse.builder()
            .userId(user.getUserId())
            .nickname(user.getNickname())
            .gender(user.getGender())
            .build();
    }
}
