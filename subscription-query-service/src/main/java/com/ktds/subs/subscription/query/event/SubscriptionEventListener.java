package com.ktds.subs.subscription.query.event;

import com.ktds.subs.subscription.query.domain.SubscriptionView;
import com.ktds.subs.subscription.query.repository.SubscriptionViewRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SubscriptionEventListener {

    private final SubscriptionViewRepository subscriptionViewRepository;

    @KafkaListener(topics = "subscription-events", groupId = "${spring.kafka.consumer.group-id}")
    public void handleSubscriptionEvent(SubscriptionEvent event) {
        switch (event.getEventType()) {
            case "SUBSCRIPTION_CREATED":
                handleSubscriptionCreated(event);
                break;
            case "SUBSCRIPTION_UPDATED":
                handleSubscriptionUpdated(event);
                break;
            case "SUBSCRIPTION_DELETED":
                handleSubscriptionDeleted(event);
                break;
        }
    }

    private void handleSubscriptionCreated(SubscriptionEvent event) {
        SubscriptionView view = new SubscriptionView();
        updateSubscriptionView(view, event);
        subscriptionViewRepository.save(view);
    }

    private void handleSubscriptionUpdated(SubscriptionEvent event) {
        subscriptionViewRepository.findById(event.getSubscriptionId())
            .ifPresent(view -> {
                updateSubscriptionView(view, event);
                subscriptionViewRepository.save(view);
            });
    }

    private void handleSubscriptionDeleted(SubscriptionEvent event) {
        subscriptionViewRepository.deleteById(event.getSubscriptionId());
    }

    private void updateSubscriptionView(SubscriptionView view, SubscriptionEvent event) {
        view.setSubscriptionId(event.getSubscriptionId());
        view.setUserId(event.getUserId());
        view.setServiceName(event.getServiceName());
        view.setCategory(event.getCategory());
        view.setPaymentAmount(event.getPaymentAmount());
        view.setPaymentCycle(event.getPaymentCycle());
        view.setPaymentDay(event.getPaymentDay());
    }
}
