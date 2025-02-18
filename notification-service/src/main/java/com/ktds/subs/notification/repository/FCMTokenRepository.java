package com.ktds.subs.notification.repository;

import com.ktds.subs.notification.domain.FCMToken;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface FCMTokenRepository extends JpaRepository<FCMToken, Long> {
    List<FCMToken> findByUserId(String userId);
}
