package com.ktds.subs.notification.repository;

import com.ktds.subs.notification.domain.NotificationHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface NotificationHistoryRepository extends JpaRepository<NotificationHistory, Long> {
    List<NotificationHistory> findByUserIdOrderBySentAtDesc(String userId);
}
