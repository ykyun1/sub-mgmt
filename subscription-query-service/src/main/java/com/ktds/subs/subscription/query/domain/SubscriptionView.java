package com.ktds.subs.subscription.query.domain;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import java.time.LocalDateTime;

@Document(collection = "subscription_views")
@Getter
@Setter
public class SubscriptionView {
    @Id
    private Long subscriptionId;
    
    private String userId;
    private String serviceName;
    private String category;
    private Long paymentAmount;
    private String paymentCycle;
    private Integer paymentDay;
    private LocalDateTime startDate;
    private LocalDateTime lastPaymentDate;
    private LocalDateTime nextPaymentDate;
    private Integer totalPayments;
    private Long totalAmount;
    private Double avgMonthlyAmount;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
