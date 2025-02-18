package com.ktds.subs.subscription.command.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "subscriptions")
@Getter
@NoArgsConstructor
public class Subscription {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "subscription_id")
    private Long subscriptionId;
    
    @Column(name = "user_id")
    private String userId;
    
    @Column(name = "service_name")
    private String serviceName;
    
    private String category;
    
    @Column(name = "payment_amount")
    private Long paymentAmount;
    
    @Column(name = "payment_cycle")
    private String paymentCycle;
    
    @Column(name = "payment_day")
    private Integer paymentDay;
    
    @Column(name = "start_date")
    private LocalDateTime startDate;
    
    @Column(name = "last_payment_date")
    private LocalDateTime lastPaymentDate;
    
    @Column(name = "next_payment_date")
    private LocalDateTime nextPaymentDate;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        startDate = LocalDateTime.now();
        calculateNextPaymentDate();
    }
    
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
        calculateNextPaymentDate();
    }
    
    private void calculateNextPaymentDate() {
        // 다음 결제일 계산 로직
        if (lastPaymentDate == null) {
            lastPaymentDate = startDate;
        }
        
        // payment_cycle에 따른 다음 결제일 계산
        switch (paymentCycle.toUpperCase()) {
            case "MONTHLY":
                nextPaymentDate = lastPaymentDate.plusMonths(1);
                break;
            case "YEARLY":
                nextPaymentDate = lastPaymentDate.plusYears(1);
                break;
            default:
                nextPaymentDate = lastPaymentDate.plusMonths(1);
        }
    }
}
