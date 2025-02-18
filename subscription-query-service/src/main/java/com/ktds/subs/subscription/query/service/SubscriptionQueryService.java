package com.ktds.subs.subscription.query.service;

import com.ktds.subs.subscription.query.dto.response.DashboardResponse;
import com.ktds.subs.subscription.query.dto.response.PaymentScheduleResponse;
import com.ktds.subs.subscription.query.dto.response.TotalAmountResponse;
import java.util.List;

public interface SubscriptionQueryService {
    DashboardResponse getDashboard(String userId);
    List<SubscriptionView> getSubscriptionsByCategory(String userId, String category);
    List<PaymentScheduleResponse> getPaymentSchedule(String userId, String yearMonth);
    TotalAmountResponse getTotalAmount(String userId, String yearMonth);
}
