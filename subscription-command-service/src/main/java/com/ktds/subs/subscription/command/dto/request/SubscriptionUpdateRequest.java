package com.ktds.subs.subscription.command.dto.request;

import jakarta.validation.constraints.Positive;
import lombok.Getter;

@Getter
public class SubscriptionUpdateRequest {
    @Positive(message = "결제금액은 양수여야 합니다.")
    private Long paymentAmount;
    
    private String paymentCycle;
    private Integer paymentDay;
    private String category;
}
