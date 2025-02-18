package com.ktds.subs.subscription.command.event;

import lombok.Getter;
import lombok.Builder;
import java.time.LocalDateTime;

@Getter
@Builder
public class SubscriptionEvent {
    private String eventType;
    private Long subscriptionId;
    private String userId;
    private String serviceName;
    private String category;
    private Long paymentAmount;
    private String paymentCycle;
    private Integer paymentDay;
    private LocalDateTime eventTime;
}
