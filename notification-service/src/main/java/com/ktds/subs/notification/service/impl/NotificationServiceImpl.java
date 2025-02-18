package com.ktds.subs.notification.service.impl;

import com.ktds.subs.notification.domain.FCMToken;
import com.ktds.subs.notification.domain.NotificationHistory;
import com.ktds.subs.notification.domain.NotificationSetting;
import com.ktds.subs.notification.dto.request.FCMTokenRequest;
import com.ktds.subs.notification.dto.response.TokenRegistrationResponse;
import com.ktds.subs.notification.repository.FCMTokenRepository;
import com.ktds.subs.notification.repository.NotificationHistoryRepository;
import com.ktds.subs.notification.repository.NotificationSettingRepository;
import com.ktds.subs.notification.service.NotificationService;
import com.ktds.subs.subscription.command.event.SubscriptionEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class NotificationServiceImpl implements NotificationService {

    private final FCMTokenRepository fcmTokenRepository;
    private final NotificationSettingRepository notificationSettingRepository;
    private final NotificationHistoryRepository notificationHistoryRepository;
    private final FirebaseMessagingService firebaseMessagingService;

    @Override
    @Transactional
    public TokenRegistrationResponse registerToken(String userId, FCMTokenRequest request) {
        FCMToken fcmToken = new FCMToken();
        fcmToken.setUserId(userId);
        fcmToken.setFcmToken(request.getToken());
        fcmToken.setDeviceInfo(request.getDeviceInfo());
        fcmTokenRepository.save(fcmToken);

        return new TokenRegistrationResponse(
            "SUCCESS",
            "FCM 토큰이 등록되었습니다.",
            LocalDateTime.now()
        );
    }

    @Override
    @Transactional
    public void handleSubscriptionEvent(SubscriptionEvent event) {
        switch (event.getEventType()) {
            case "SUBSCRIPTION_CREATED":
                sendWelcomeNotification(event);
                break;
            case "SUBSCRIPTION_UPDATED":
                sendUpdateNotification(event);
                break;
            case "SUBSCRIPTION_DELETED":
                sendDeleteNotification(event);
                break;
        }
    }

    @Override
    @Transactional
    public void sendPaymentNotification(String userId, Long subscriptionId, String serviceName, Long paymentAmount) {
        NotificationSetting setting = notificationSettingRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("알림 설정을 찾을 수 없습니다."));

        if (!setting.isPaymentNotification()) {
            return;
        }

        List<FCMToken> tokens = fcmTokenRepository.findByUserId(userId);
        String title = "결제 예정 알림";
        String message = String.format("%s 서비스의 결제(%,d원)가 예정되어 있습니다.", serviceName, paymentAmount);

        tokens.forEach(token -> {
            try {
                firebaseMessagingService.sendMessage(token.getFcmToken(), title, message);
                saveNotificationHistory(userId, subscriptionId, "PAYMENT", title, message);
            } catch (Exception e) {
                // 토큰이 만료되었거나 유효하지 않은 경우 처리
                fcmTokenRepository.delete(token);
            }
        });
    }

    private void sendWelcomeNotification(SubscriptionEvent event) {
        String title = "구독 서비스 등록";
        String message = String.format("%s 서비스가 등록되었습니다.", event.getServiceName());
        sendNotification(event.getUserId(), event.getSubscriptionId(), "WELCOME", title, message);
    }

    private void sendUpdateNotification(SubscriptionEvent event) {
        String title = "구독 서비스 수정";
        String message = String.format("%s 서비스 정보가 수정되었습니다.", event.getServiceName());
        sendNotification(event.getUserId(), event.getSubscriptionId(), "UPDATE", title, message);
    }

    private void sendDeleteNotification(SubscriptionEvent event) {
        String title = "구독 서비스 삭제";
        String message = String.format("%s 서비스가 삭제되었습니다.", event.getServiceName());
        sendNotification(event.getUserId(), event.getSubscriptionId(), "DELETE", title, message);
    }

    private void sendNotification(String userId, Long subscriptionId, String type, String title, String message) {
        List<FCMToken> tokens = fcmTokenRepository.findByUserId(userId);
        tokens.forEach(token -> {
            try {
                firebaseMessagingService.sendMessage(token.getFcmToken(), title, message);
                saveNotificationHistory(userId, subscriptionId, type, title, message);
            } catch (Exception e) {
                fcmTokenRepository.delete(token);
            }
        });
    }

    private void saveNotificationHistory(String userId, Long subscriptionId, String type, String title, String message) {
        NotificationHistory history = new NotificationHistory();
        history.setUserId(userId);
        history.setSubscriptionId(subscriptionId);
        history.setNotificationType(type);
        history.setTitle(title);
        history.setMessage(message);
        history.setSentAt(LocalDateTime.now());
        notificationHistoryRepository.save(history);
    }
}
