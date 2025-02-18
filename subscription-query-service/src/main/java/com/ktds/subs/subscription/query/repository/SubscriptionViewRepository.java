package com.ktds.subs.subscription.query.repository;

import com.ktds.subs.subscription.query.domain.SubscriptionView;
import org.springframework.data.mongodb.repository.MongoRepository;
import java.util.List;

public interface SubscriptionViewRepository extends MongoRepository<SubscriptionView, Long> {
    List<SubscriptionView> findByUserId(String userId);
    List<SubscriptionView> findByUserIdAndCategory(String userId, String category);
}
