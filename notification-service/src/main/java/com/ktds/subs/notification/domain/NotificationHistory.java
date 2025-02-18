package com.ktds.subs.notification.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "notification_history")
@Getter
@NoArgsConstructor
public class NotificationHistory {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "notification_id")
    private Long notificationId;
    
    @Column(name = "user_id")
    private String userId;
    
    @Column(name = "subscription_id")
    private Long subscriptionId;
    
    @Column(name = "notification_type")
    private String notificationType;
    
    private String title;
    
    private String message;
    
    @Column(name = "sent_at")
    private LocalDateTime sentAt;
    
    @Column(name = "read_at")
    private LocalDateTime readAt;
}
