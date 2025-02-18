package com.ktds.subs.auth.service;

import com.ktds.subs.auth.dto.request.UserProfileRequest;
import com.ktds.subs.auth.dto.request.NotificationSettingRequest;
import com.ktds.subs.auth.dto.response.UserProfileResponse;
import com.ktds.subs.auth.dto.response.NotificationSettingResponse;

public interface UserService {
    UserProfileResponse getProfile(String userId);
    UserProfileResponse updateProfile(String userId, UserProfileRequest request);
    NotificationSettingResponse getNotificationSettings(String userId);
    NotificationSettingResponse updateNotificationSettings(String userId, NotificationSettingRequest request);
}
