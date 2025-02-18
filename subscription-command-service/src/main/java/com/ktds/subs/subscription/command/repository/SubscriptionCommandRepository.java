package com.ktds.subs.subscription.command.repository;

import com.ktds.subs.subscription.command.domain.Subscription;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SubscriptionCommandRepository extends JpaRepository<Subscription, Long> {
    boolean existsByUserIdAndServiceNameAndDeletedAtIsNull(String userId, String serviceName);
}
