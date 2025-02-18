package com.ktds.subs.subscription.command.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.Getter;

@Getter
public class SubscriptionCreateRequest {
    @NotBlank(message = "서비스명은 필수입니다.")
    private String serviceName;
    
    @NotBlank(message = "카테고리는 필수입니다.")
    private String category;
    
    @NotNull(message = "결제금액은 필수입니다.")
    @Positive(message = "결제금액은 양수여야 합니다.")
    private Long paymentAmount;
    
    @NotBlank(message = "결제주기는 필수입니다.")
    private String paymentCycle;
    
    @NotNull(message = "결제일은 필수입니다.")
    private Integer paymentDay;
}
