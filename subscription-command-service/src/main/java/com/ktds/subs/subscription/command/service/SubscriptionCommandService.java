package com.ktds.subs.subscription.command.service;

import com.ktds.subs.subscription.command.dto.request.SubscriptionCreateRequest;
import com.ktds.subs.subscription.command.dto.request.SubscriptionUpdateRequest;
import com.ktds.subs.subscription.command.dto.response.SubscriptionResponse;
import com.ktds.subs.subscription.command.dto.response.DeleteResponse;

public interface SubscriptionCommandService {
    SubscriptionResponse createSubscription(String userId, SubscriptionCreateRequest request);
    SubscriptionResponse updateSubscription(String userId, Long subscriptionId, SubscriptionUpdateRequest request);
    DeleteResponse deleteSubscription(String userId, Long subscriptionId);
}
