package com.ktds.subs.notification.event;

import com.ktds.subs.notification.service.NotificationService;
import com.ktds.subs.subscription.command.event.SubscriptionEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SubscriptionEventListener {

    private final NotificationService notificationService;

    @KafkaListener(topics = "subscription-events", groupId = "${spring.kafka.consumer.group-id}")
    public void handleSubscriptionEvent(SubscriptionEvent event) {
        notificationService.handleSubscriptionEvent(event);
    }
}
