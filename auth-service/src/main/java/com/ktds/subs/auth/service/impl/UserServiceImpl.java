package com.ktds.subs.auth.service.impl;

import com.ktds.subs.auth.domain.User;
import com.ktds.subs.auth.dto.request.UserProfileRequest;
import com.ktds.subs.auth.dto.request.NotificationSettingRequest;
import com.ktds.subs.auth.dto.response.UserProfileResponse;
import com.ktds.subs.auth.dto.response.NotificationSettingResponse;
import com.ktds.subs.auth.repository.UserRepository;
import com.ktds.subs.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserProfileResponse getProfile(String userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        return UserProfileResponse.from(user);
    }

    @Override
    @Transactional
    public UserProfileResponse updateProfile(String userId, UserProfileRequest request) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        
        user.setNickname(request.getNickname());
        user.setGender(request.getGender());
        
        return UserProfileResponse.from(userRepository.save(user));
    }

    @Override
    @Transactional(readOnly = true)
    public NotificationSettingResponse getNotificationSettings(String userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        return NotificationSettingResponse.from(user);
    }

    @Override
    @Transactional
    public NotificationSettingResponse updateNotificationSettings(String userId, NotificationSettingRequest request) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        
        user.setNotificationEnabled(request.isEnabled());
        
        return NotificationSettingResponse.from(userRepository.save(user));
    }
}
