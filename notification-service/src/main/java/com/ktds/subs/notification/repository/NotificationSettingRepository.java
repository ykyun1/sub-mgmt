package com.ktds.subs.notification.repository;

import com.ktds.subs.notification.domain.NotificationSetting;
import org.springframework.data.jpa.repository.JpaRepository;

public interface NotificationSettingRepository extends JpaRepository<NotificationSetting, String> {
}
