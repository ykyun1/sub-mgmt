package com.ktds.subs.subscription.query.service.impl;

import com.ktds.subs.subscription.query.domain.SubscriptionView;
import com.ktds.subs.subscription.query.dto.response.DashboardResponse;
import com.ktds.subs.subscription.query.dto.response.PaymentScheduleResponse;
import com.ktds.subs.subscription.query.dto.response.TotalAmountResponse;
import com.ktds.subs.subscription.query.repository.SubscriptionViewRepository;
import com.ktds.subs.subscription.query.service.SubscriptionQueryService;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.YearMonth;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class SubscriptionQueryServiceImpl implements SubscriptionQueryService {

    private final SubscriptionViewRepository subscriptionViewRepository;

    @Override
    @Cacheable(value = "dashboards", key = "#userId")
    public DashboardResponse getDashboard(String userId) {
        List<SubscriptionView> subscriptions = subscriptionViewRepository.findByUserId(userId);
        
        Long totalAmount = subscriptions.stream()
            .mapToLong(SubscriptionView::getPaymentAmount)
            .sum();
            
        List<DashboardResponse.SubscriptionSummary> summaries = subscriptions.stream()
            .map(this::toSummary)
            .collect(Collectors.toList());
            
        return DashboardResponse.builder()
            .totalAmount(totalAmount)
            .subscriptions(summaries)
            .build();
    }

    @Override
    public List<SubscriptionView> getSubscriptionsByCategory(String userId, String category) {
        return subscriptionViewRepository.findByUserIdAndCategory(userId, category);
    }

    @Override
    public List<PaymentScheduleResponse> getPaymentSchedule(String userId, String yearMonth) {
        YearMonth ym = YearMonth.parse(yearMonth);
        List<SubscriptionView> subscriptions = subscriptionViewRepository.findByUserId(userId);
        
        return subscriptions.stream()
            .filter(sub -> isPaymentDueInMonth(sub, ym))
            .map(this::toPaymentSchedule)
            .collect(Collectors.toList());
    }

    @Override
    @Cacheable(value = "monthlyTotals", key = "#userId + ':' + #yearMonth")
    public TotalAmountResponse getTotalAmount(String userId, String yearMonth) {
        YearMonth ym = YearMonth.parse(yearMonth);
        List<SubscriptionView> subscriptions = subscriptionViewRepository.findByUserId(userId);
        
        Long totalAmount = subscriptions.stream()
            .filter(sub -> isPaymentDueInMonth(sub, ym))
            .mapToLong(SubscriptionView::getPaymentAmount)
            .sum();
            
        return new TotalAmountResponse(totalAmount);
    }

    private DashboardResponse.SubscriptionSummary toSummary(SubscriptionView subscription) {
        return DashboardResponse.SubscriptionSummary.builder()
            .subscriptionId(subscription.getSubscriptionId())
            .serviceName(subscription.getServiceName())
            .category(subscription.getCategory())
            .paymentAmount(subscription.getPaymentAmount())
            .paymentCycle(subscription.getPaymentCycle())
            .nextPaymentDate(subscription.getNextPaymentDate())
            .build();
    }

    private PaymentScheduleResponse toPaymentSchedule(SubscriptionView subscription) {
        return PaymentScheduleResponse.builder()
            .serviceId(subscription.getSubscriptionId())
            .serviceName(subscription.getServiceName())
            .paymentAmount(subscription.getPaymentAmount())
            .paymentDay(subscription.getPaymentDay())
            .build();
    }

    private boolean isPaymentDueInMonth(SubscriptionView subscription, YearMonth yearMonth) {
        LocalDateTime nextPayment = subscription.getNextPaymentDate();
        return YearMonth.from(nextPayment).equals(yearMonth);
    }
}
