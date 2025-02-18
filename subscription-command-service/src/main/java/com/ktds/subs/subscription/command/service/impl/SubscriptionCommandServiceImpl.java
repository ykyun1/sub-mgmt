package com.ktds.subs.subscription.command.service.impl;

import com.ktds.subs.subscription.command.domain.Subscription;
import com.ktds.subs.subscription.command.dto.request.SubscriptionCreateRequest;
import com.ktds.subs.subscription.command.dto.request.SubscriptionUpdateRequest;
import com.ktds.subs.subscription.command.dto.response.DeleteResponse;
import com.ktds.subs.subscription.command.dto.response.SubscriptionResponse;
import com.ktds.subs.subscription.command.event.SubscriptionEvent;
import com.ktds.subs.subscription.command.repository.SubscriptionCommandRepository;
import com.ktds.subs.subscription.command.service.SubscriptionCommandService;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class SubscriptionCommandServiceImpl implements SubscriptionCommandService {

    private final SubscriptionCommandRepository subscriptionRepository;
    private final KafkaTemplate<String, SubscriptionEvent> kafkaTemplate;
    private static final String TOPIC = "subscription-events";

    @Override
    @Transactional
    public SubscriptionResponse createSubscription(String userId, SubscriptionCreateRequest request) {
        // 중복 구독 체크
        if (subscriptionRepository.existsByUserIdAndServiceNameAndDeletedAtIsNull(userId, request.getServiceName())) {
            throw new RuntimeException("이미 구독 중인 서비스입니다.");
        }

        // 구독 생성
        Subscription subscription = new Subscription();
        subscription.setUserId(userId);
        subscription.setServiceName(request.getServiceName());
        subscription.setCategory(request.getCategory());
        subscription.setPaymentAmount(request.getPaymentAmount());
        subscription.setPaymentCycle(request.getPaymentCycle());
        subscription.setPaymentDay(request.getPaymentDay());

        Subscription savedSubscription = subscriptionRepository.save(subscription);

        // 이벤트 발행
        publishSubscriptionEvent("SUBSCRIPTION_CREATED", savedSubscription);

        return SubscriptionResponse.from(savedSubscription);
    }

    @Override
    @Transactional
    public SubscriptionResponse updateSubscription(String userId, Long subscriptionId, SubscriptionUpdateRequest request) {
        Subscription subscription = subscriptionRepository.findById(subscriptionId)
            .orElseThrow(() -> new RuntimeException("구독 정보를 찾을 수 없습니다."));

        if (!subscription.getUserId().equals(userId)) {
            throw new RuntimeException("수정 권한이 없습니다.");
        }

        // 구독 정보 업데이트
        subscription.update(request);
        Subscription updatedSubscription = subscriptionRepository.save(subscription);

        // 이벤트 발행
        publishSubscriptionEvent("SUBSCRIPTION_UPDATED", updatedSubscription);

        return SubscriptionResponse.from(updatedSubscription);
    }

    @Override
    @Transactional
    public DeleteResponse deleteSubscription(String userId, Long subscriptionId) {
        Subscription subscription = subscriptionRepository.findById(subscriptionId)
            .orElseThrow(() -> new RuntimeException("구독 정보를 찾을 수 없습니다."));

        if (!subscription.getUserId().equals(userId)) {
            throw new RuntimeException("삭제 권한이 없습니다.");
        }

        subscription.setDeletedAt(LocalDateTime.now());
        subscriptionRepository.save(subscription);

        // 이벤트 발행
        publishSubscriptionEvent("SUBSCRIPTION_DELETED", subscription);

        return new DeleteResponse("SUCCESS", "구독이 삭제되었습니다.", LocalDateTime.now());
    }

    private void publishSubscriptionEvent(String eventType, Subscription subscription) {
        SubscriptionEvent event = SubscriptionEvent.builder()
            .eventType(eventType)
            .subscriptionId(subscription.getSubscriptionId())
            .userId(subscription.getUserId())
            .serviceName(subscription.getServiceName())
            .category(subscription.getCategory())
            .paymentAmount(subscription.getPaymentAmount())
            .paymentCycle(subscription.getPaymentCycle())
            .paymentDay(subscription.getPaymentDay())
            .eventTime(LocalDateTime.now())
            .build();

        kafkaTemplate.send(TOPIC, event);
    }
}
