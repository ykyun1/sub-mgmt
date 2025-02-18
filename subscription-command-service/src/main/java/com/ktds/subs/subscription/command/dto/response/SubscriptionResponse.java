package com.ktds.subs.subscription.command.dto.response;

import com.ktds.subs.subscription.command.domain.Subscription;
import lombok.Getter;
import lombok.Builder;

import java.time.LocalDateTime;

@Getter
@Builder
public class SubscriptionResponse {
    private Long subscriptionId;
    private String serviceName;
    private String category;
    private Long paymentAmount;
    private String paymentCycle;
    private Integer paymentDay;
    private LocalDateTime startDate;
    private LocalDateTime lastPaymentDate;
    private LocalDateTime nextPaymentDate;
    
    public static SubscriptionResponse from(Subscription subscription) {
        return SubscriptionResponse.builder()
            .subscriptionId(subscription.getSubscriptionId())
            .serviceName(subscription.getServiceName())
            .category(subscription.getCategory())
            .paymentAmount(subscription.getPaymentAmount())
            .paymentCycle(subscription.getPaymentCycle())
            .paymentDay(subscription.getPaymentDay())
            .startDate(subscription.getStartDate())
            .lastPaymentDate(subscription.getLastPaymentDate())
            .nextPaymentDate(subscription.getNextPaymentDate())
            .build();
    }
}
