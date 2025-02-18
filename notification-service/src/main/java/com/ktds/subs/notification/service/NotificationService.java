package com.ktds.subs.notification.service;

import com.ktds.subs.notification.dto.request.FCMTokenRequest;
import com.ktds.subs.notification.dto.response.TokenRegistrationResponse;
import com.ktds.subs.subscription.command.event.SubscriptionEvent;

public interface NotificationService {
    TokenRegistrationResponse registerToken(String userId, FCMTokenRequest request);
    void handleSubscriptionEvent(SubscriptionEvent event);
    void sendPaymentNotification(String userId, Long subscriptionId, String serviceName, Long paymentAmount);
}
