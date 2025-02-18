package com.ktds.subs.subscription.query.dto.response;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class PaymentScheduleResponse {
    private Long serviceId;
    private String serviceName;
    private Long paymentAmount;
    private Integer paymentDay;
}
