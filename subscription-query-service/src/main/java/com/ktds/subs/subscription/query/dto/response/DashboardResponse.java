package com.ktds.subs.subscription.query.dto.response;

import lombok.Builder;
import lombok.Getter;
import java.util.List;

@Getter
@Builder
public class DashboardResponse {
    private Long totalAmount;
    private List<SubscriptionSummary> subscriptions;
    
    @Getter
    @Builder
    public static class SubscriptionSummary {
        private Long subscriptionId;
        private String serviceName;
        private String category;
        private Long paymentAmount;
        private String paymentCycle;
        private LocalDateTime nextPaymentDate;
    }
}
