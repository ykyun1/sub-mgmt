// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/settings.gradle
rootProject.name = 'subs-mgmt'

include 'common'
include 'auth-service'
include 'subscription-command-service'
include 'subscription-query-service'
include 'notification-service'
include 'api-gateway'


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/build.gradle
dependencies {
    implementation project(':common')
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    implementation 'org.springframework.kafka:spring-kafka'
    implementation 'com.google.firebase:firebase-admin:9.2.0'
    implementation 'mysql:mysql-connector-java:8.0.33'
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/resources/application.yml
spring:
  application:
    name: ${SPRING_APPLICATION_NAME:notification-service}
  datasource:
    url: ${DATASOURCE_URL}
    username: ${DATASOURCE_USERNAME}
    password: ${DATASOURCE_PASSWORD}
    driver-class-name: com.mysql.cj.jdbc.Driver
  jpa:
    hibernate:
      ddl-auto: validate
    properties:
      hibernate:
        format_sql: true
        show_sql: true
  kafka:
    bootstrap-servers: ${KAFKA_BOOTSTRAP_SERVERS}
    consumer:
      group-id: ${KAFKA_CONSUMER_GROUP_ID:notification-service}
      auto-offset-reset: earliest

server:
  port: ${SERVER_PORT:8084}

firebase:
  config:
    path: ${FIREBASE_CONFIG_PATH:firebase-service-account.json}
    

// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/NotificationServiceApplication.java
package com.ktds.subs.notification;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class NotificationServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(NotificationServiceApplication.class, args);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/dto/response/TokenRegistrationResponse.java
package com.ktds.subs.notification.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import java.time.LocalDateTime;

@Getter
@AllArgsConstructor
public class TokenRegistrationResponse {
    private String status;
    private String message;
    private LocalDateTime registeredAt;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/dto/request/FCMTokenRequest.java
package com.ktds.subs.notification.dto.request;

import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class FCMTokenRequest {
    private String token;
    private String deviceInfo;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/repository/NotificationHistoryRepository.java
package com.ktds.subs.notification.repository;

import com.ktds.subs.notification.domain.NotificationHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface NotificationHistoryRepository extends JpaRepository<NotificationHistory, Long> {
    List<NotificationHistory> findByUserIdOrderBySentAtDesc(String userId);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/repository/FCMTokenRepository.java
package com.ktds.subs.notification.repository;

import com.ktds.subs.notification.domain.FCMToken;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface FCMTokenRepository extends JpaRepository<FCMToken, Long> {
    List<FCMToken> findByUserId(String userId);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/repository/NotificationSettingRepository.java
package com.ktds.subs.notification.repository;

import com.ktds.subs.notification.domain.NotificationSetting;
import org.springframework.data.jpa.repository.JpaRepository;

public interface NotificationSettingRepository extends JpaRepository<NotificationSetting, String> {
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/config/KafkaConfig.java
package com.ktds.subs.notification.config;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.support.serializer.JsonDeserializer;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class KafkaConfig {

    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;

    @Value("${spring.kafka.consumer.group-id}")
    private String groupId;

    @Bean
    public ConsumerFactory<String, Object> consumerFactory() {
        Map<String, Object> props = new HashMap<>();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ConsumerConfig.GROUP_ID_CONFIG, groupId);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, JsonDeserializer.class);
        props.put(JsonDeserializer.TRUSTED_PACKAGES, "*");
        
        return new DefaultKafkaConsumerFactory<>(props);
    }

    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, Object> kafkaListenerContainerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, Object> factory = 
            new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(consumerFactory());
        return factory;
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/config/FirebaseConfig.java
package com.ktds.subs.notification.config;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.messaging.FirebaseMessaging;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;

@Configuration
public class FirebaseConfig {

    @Value("${firebase.config.path}")
    private String firebaseConfigPath;

    @Bean
    public FirebaseMessaging firebaseMessaging() throws IOException {
        GoogleCredentials googleCredentials = GoogleCredentials
            .fromStream(new ClassPathResource(firebaseConfigPath).getInputStream());

        FirebaseOptions firebaseOptions = FirebaseOptions.builder()
            .setCredentials(googleCredentials)
            .build();

        FirebaseApp app = FirebaseApp.initializeApp(firebaseOptions);
        return FirebaseMessaging.getInstance(app);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/controller/NotificationController.java
package com.ktds.subs.notification.controller;

import com.ktds.subs.common.dto.ApiResponse;
import com.ktds.subs.notification.dto.request.FCMTokenRequest;
import com.ktds.subs.notification.service.NotificationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@Tag(name = "알림", description = "알림 관련 API")
@RestController
@RequestMapping("/api/notifications")
@RequiredArgsConstructor
public class NotificationController {

    private final NotificationService notificationService;

    @Operation(summary = "FCM 토큰 등록", description = "사용자의 FCM 토큰을 등록합니다.")
    @PostMapping("/token")
    public ApiResponse<?> registerToken(
            @RequestHeader("X-User-ID") String userId,
            @RequestBody FCMTokenRequest request) {
        return ApiResponse.success(notificationService.registerToken(userId, request));
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/service/FirebaseMessagingService.java
package com.ktds.subs.notification.service;

import com.google.firebase.messaging.FirebaseMessaging;
import com.google.firebase.messaging.Message;
import com.google.firebase.messaging.Notification;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class FirebaseMessagingService {

    private final FirebaseMessaging firebaseMessaging;

    public void sendMessage(String token, String title, String body) throws Exception {
        Message message = Message.builder()
            .setNotification(Notification.builder()
                .setTitle(title)
                .setBody(body)
                .build())
            .setToken(token)
            .build();

        firebaseMessaging.send(message);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/service/NotificationService.java
package com.ktds.subs.notification.service;

import com.ktds.subs.notification.dto.request.FCMTokenRequest;
import com.ktds.subs.notification.dto.response.TokenRegistrationResponse;
import com.ktds.subs.subscription.command.event.SubscriptionEvent;

public interface NotificationService {
    TokenRegistrationResponse registerToken(String userId, FCMTokenRequest request);
    void handleSubscriptionEvent(SubscriptionEvent event);
    void sendPaymentNotification(String userId, Long subscriptionId, String serviceName, Long paymentAmount);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/service/impl/NotificationServiceImpl.java
package com.ktds.subs.notification.service.impl;

import com.ktds.subs.notification.domain.FCMToken;
import com.ktds.subs.notification.domain.NotificationHistory;
import com.ktds.subs.notification.domain.NotificationSetting;
import com.ktds.subs.notification.dto.request.FCMTokenRequest;
import com.ktds.subs.notification.dto.response.TokenRegistrationResponse;
import com.ktds.subs.notification.repository.FCMTokenRepository;
import com.ktds.subs.notification.repository.NotificationHistoryRepository;
import com.ktds.subs.notification.repository.NotificationSettingRepository;
import com.ktds.subs.notification.service.NotificationService;
import com.ktds.subs.subscription.command.event.SubscriptionEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class NotificationServiceImpl implements NotificationService {

    private final FCMTokenRepository fcmTokenRepository;
    private final NotificationSettingRepository notificationSettingRepository;
    private final NotificationHistoryRepository notificationHistoryRepository;
    private final FirebaseMessagingService firebaseMessagingService;

    @Override
    @Transactional
    public TokenRegistrationResponse registerToken(String userId, FCMTokenRequest request) {
        FCMToken fcmToken = new FCMToken();
        fcmToken.setUserId(userId);
        fcmToken.setFcmToken(request.getToken());
        fcmToken.setDeviceInfo(request.getDeviceInfo());
        fcmTokenRepository.save(fcmToken);

        return new TokenRegistrationResponse(
            "SUCCESS",
            "FCM 토큰이 등록되었습니다.",
            LocalDateTime.now()
        );
    }

    @Override
    @Transactional
    public void handleSubscriptionEvent(SubscriptionEvent event) {
        switch (event.getEventType()) {
            case "SUBSCRIPTION_CREATED":
                sendWelcomeNotification(event);
                break;
            case "SUBSCRIPTION_UPDATED":
                sendUpdateNotification(event);
                break;
            case "SUBSCRIPTION_DELETED":
                sendDeleteNotification(event);
                break;
        }
    }

    @Override
    @Transactional
    public void sendPaymentNotification(String userId, Long subscriptionId, String serviceName, Long paymentAmount) {
        NotificationSetting setting = notificationSettingRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("알림 설정을 찾을 수 없습니다."));

        if (!setting.isPaymentNotification()) {
            return;
        }

        List<FCMToken> tokens = fcmTokenRepository.findByUserId(userId);
        String title = "결제 예정 알림";
        String message = String.format("%s 서비스의 결제(%,d원)가 예정되어 있습니다.", serviceName, paymentAmount);

        tokens.forEach(token -> {
            try {
                firebaseMessagingService.sendMessage(token.getFcmToken(), title, message);
                saveNotificationHistory(userId, subscriptionId, "PAYMENT", title, message);
            } catch (Exception e) {
                // 토큰이 만료되었거나 유효하지 않은 경우 처리
                fcmTokenRepository.delete(token);
            }
        });
    }

    private void sendWelcomeNotification(SubscriptionEvent event) {
        String title = "구독 서비스 등록";
        String message = String.format("%s 서비스가 등록되었습니다.", event.getServiceName());
        sendNotification(event.getUserId(), event.getSubscriptionId(), "WELCOME", title, message);
    }

    private void sendUpdateNotification(SubscriptionEvent event) {
        String title = "구독 서비스 수정";
        String message = String.format("%s 서비스 정보가 수정되었습니다.", event.getServiceName());
        sendNotification(event.getUserId(), event.getSubscriptionId(), "UPDATE", title, message);
    }

    private void sendDeleteNotification(SubscriptionEvent event) {
        String title = "구독 서비스 삭제";
        String message = String.format("%s 서비스가 삭제되었습니다.", event.getServiceName());
        sendNotification(event.getUserId(), event.getSubscriptionId(), "DELETE", title, message);
    }

    private void sendNotification(String userId, Long subscriptionId, String type, String title, String message) {
        List<FCMToken> tokens = fcmTokenRepository.findByUserId(userId);
        tokens.forEach(token -> {
            try {
                firebaseMessagingService.sendMessage(token.getFcmToken(), title, message);
                saveNotificationHistory(userId, subscriptionId, type, title, message);
            } catch (Exception e) {
                fcmTokenRepository.delete(token);
            }
        });
    }

    private void saveNotificationHistory(String userId, Long subscriptionId, String type, String title, String message) {
        NotificationHistory history = new NotificationHistory();
        history.setUserId(userId);
        history.setSubscriptionId(subscriptionId);
        history.setNotificationType(type);
        history.setTitle(title);
        history.setMessage(message);
        history.setSentAt(LocalDateTime.now());
        notificationHistoryRepository.save(history);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/domain/NotificationHistory.java
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


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/domain/NotificationSetting.java
package com.ktds.subs.notification.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;
import java.time.LocalTime;

@Entity
@Table(name = "notification_settings")
@Getter
@NoArgsConstructor
public class NotificationSetting {
    @Id
    @Column(name = "user_id")
    private String userId;
    
    @Column(name = "payment_notification")
    private boolean paymentNotification;
    
    @Column(name = "notification_time")
    private LocalTime notificationTime;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
    
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/domain/FCMToken.java
package com.ktds.subs.notification.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "fcm_tokens")
@Getter
@NoArgsConstructor
public class FCMToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "token_id")
    private Long tokenId;
    
    @Column(name = "user_id")
    private String userId;
    
    @Column(name = "fcm_token")
    private String fcmToken;
    
    @Column(name = "device_info")
    private String deviceInfo;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/event/SubscriptionEventListener.java
package com.ktds.subs.notification.event;

import com.ktds.subs.notification.service.NotificationService;
import com.ktds.subs.subscription.command.event.SubscriptionEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SubscriptionEventListener {

    private final NotificationService notificationService;

    @KafkaListener(topics = "subscription-events", groupId = "${spring.kafka.consumer.group-id}")
    public void handleSubscriptionEvent(SubscriptionEvent event) {
        notificationService.handleSubscriptionEvent(event);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/api-gateway/build.gradle
dependencies {
    implementation 'org.springframework.cloud:spring-cloud-starter-gateway'
    implementation 'org.springframework.cloud:spring-cloud-starter-netflix-eureka-client'
    implementation 'org.springframework.boot:spring-boot-starter-security'
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/api-gateway/src/main/resources/application.yml
spring:
  application:
    name: ${SPRING_APPLICATION_NAME:api-gateway}
  cloud:
    gateway:
      routes:
        - id: auth-service
          uri: lb://auth-service
          predicates:
            - Path=/api/auth/**
          filters:
            - RewritePath=/api/auth/(?<segment>.*), /api/auth/${segment}

        - id: subscription-command-service
          uri: lb://subscription-command-service
          predicates:
            - Path=/api/subscriptions/**
            - Method=POST,PUT,DELETE
          filters:
            - RewritePath=/api/subscriptions/(?<segment>.*), /api/subscriptions/${segment}

        - id: subscription-query-service
          uri: lb://subscription-query-service
          predicates:
            - Path=/api/subscriptions/**
            - Method=GET
          filters:
            - RewritePath=/api/subscriptions/(?<segment>.*), /api/subscriptions/${segment}

        - id: notification-service
          uri: lb://notification-service
          predicates:
            - Path=/api/notifications/**
          filters:
            - RewritePath=/api/notifications/(?<segment>.*), /api/notifications/${segment}

  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: ${JWT_JWK_SET_URI}

server:
  port: ${SERVER_PORT:8080}

eureka:
  client:
    service-url:
      defaultZone: ${EUREKA_SERVICE_URL:http://localhost:8761/eureka/}
    fetch-registry: true
    register-with-eureka: true
  instance:
    prefer-ip-address: true

jwt:
  secret: ${JWT_SECRET}

management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics
        


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/api-gateway/src/main/java/com/ktds/subs/gateway/ApiGatewayApplication.java
package com.ktds.subs.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class ApiGatewayApplication {
    public static void main(String[] args) {
        SpringApplication.run(ApiGatewayApplication.class, args);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/api-gateway/src/main/java/com/ktds/subs/gateway/util/JwtTokenProvider.java
package com.ktds.subs.gateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Component
public class JwtTokenProvider {

    private final SecretKey key;

    public JwtTokenProvider(@Value("${jwt.secret}") String secret) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public String getUserId(String token) {
        Claims claims = Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)
            .getBody();
        return claims.getSubject();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/api-gateway/src/main/java/com/ktds/subs/gateway/config/SecurityConfig.java
package com.ktds.subs.gateway.config;

import com.ktds.subs.gateway.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
            .csrf().disable()
            .formLogin().disable()
            .httpBasic().disable()
            .authorizeExchange()
            .pathMatchers("/api/auth/**").permitAll()
            .pathMatchers("/actuator/**").permitAll()
            .anyExchange().authenticated()
            .and()
            .addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
            .build();
    }

    @Bean
    public CorsWebFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList("*"));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(Arrays.asList("*"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return new CorsWebFilter(source);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/api-gateway/src/main/java/com/ktds/subs/gateway/filter/JwtAuthenticationFilter.java
package com.ktds.subs.gateway.filter;

import com.ktds.subs.gateway.util.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        
        // Skip authentication for public endpoints
        if (path.startsWith("/api/auth/") || path.startsWith("/actuator/")) {
            return chain.filter(exchange);
        }

        String token = extractToken(exchange);
        
        if (token == null || !jwtTokenProvider.validateToken(token)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // Add user ID to request header
        String userId = jwtTokenProvider.getUserId(token);
        ServerWebExchange modifiedExchange = exchange.mutate()
            .request(exchange.getRequest().mutate()
                .header("X-User-ID", userId)
                .build())
            .build();

        return chain.filter(modifiedExchange);
    }

    private String extractToken(ServerWebExchange exchange) {
        String bearerToken = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/common/build.gradle
dependencies {
    implementation 'com.fasterxml.jackson.core:jackson-databind'
    implementation 'org.springframework.boot:spring-boot-starter-web'
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/common/src/main/resources/application.yml
server:
  port: ${SERVER_PORT:0}

spring:
  application:
    name: ${SPRING_APPLICATION_NAME}
  
  jpa:
    hibernate:
      ddl-auto: validate
    properties:
      hibernate:
        format_sql: true
        show_sql: true
        
logging:
  level:
    root: INFO
    com.ktds: DEBUG


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/common/src/main/java/com/ktds/subs/common/dto/ApiResponse.java
package com.ktds.subs.common.dto;

import lombok.Getter;
import java.time.LocalDateTime;

@Getter
public class ApiResponse<T> {
    private final String status;
    private final String message;
    private final T data;
    private final LocalDateTime timestamp;

    private ApiResponse(String status, String message, T data) {
        this.status = status;
        this.message = message;
        this.data = data;
        this.timestamp = LocalDateTime.now();
    }

    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>("SUCCESS", null, data);
    }

    public static <T> ApiResponse<T> error(String message) {
        return new ApiResponse<>("ERROR", message, null);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/common/src/main/java/com/ktds/subs/common/constant/ErrorCode.java
package com.ktds.subs.common.constant;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {
    // Common Errors
    INVALID_INPUT_VALUE("C001", "Invalid Input Value"),
    METHOD_NOT_ALLOWED("C002", "Method Not Allowed"),
    ENTITY_NOT_FOUND("C003", "Entity Not Found"),
    INTERNAL_SERVER_ERROR("C004", "Internal Server Error"),
    INVALID_TYPE_VALUE("C005", "Invalid Type Value"),
    ACCESS_DENIED("C006", "Access Denied"),
    
    // Auth Errors
    INVALID_AUTH_TOKEN("A001", "Invalid Auth Token"),
    EXPIRED_AUTH_TOKEN("A002", "Expired Auth Token"),
    UNAUTHORIZED("A003", "Unauthorized"),
    INVALID_SOCIAL_TOKEN("A004", "Invalid Social Token"),
    
    // Subscription Errors
    DUPLICATE_SUBSCRIPTION("S001", "Duplicate Subscription"),
    INVALID_SUBSCRIPTION("S002", "Invalid Subscription"),
    SUBSCRIPTION_NOT_FOUND("S003", "Subscription Not Found"),
    
    // Notification Errors
    NOTIFICATION_SEND_FAILED("N001", "Notification Send Failed"),
    INVALID_FCM_TOKEN("N002", "Invalid FCM Token");

    private final String code;
    private final String message;
}









    
    
    

// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/common/src/main/java/com/ktds/subs/common/exception/BaseException.java
package com.ktds.subs.common.exception;

import lombok.Getter;

@Getter
public class BaseException extends RuntimeException {
    private final String errorCode;
    
    public BaseException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/build.gradle
dependencies {
    implementation project(':common')
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    implementation 'org.springframework.kafka:spring-kafka'
    implementation 'mysql:mysql-connector-java:8.0.33'
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/resources/application.yml
spring:
  application:
    name: ${SPRING_APPLICATION_NAME:subscription-command-service}
  datasource:
    url: ${DATASOURCE_URL}
    username: ${DATASOURCE_USERNAME}
    password: ${DATASOURCE_PASSWORD}
    driver-class-name: com.mysql.cj.jdbc.Driver
  jpa:
    hibernate:
      ddl-auto: validate
    properties:
      hibernate:
        format_sql: true
        show_sql: true
  kafka:
    bootstrap-servers: ${KAFKA_BOOTSTRAP_SERVERS}
    producer:
      key-serializer: org.apache.kafka.common.serialization.StringSerializer
      value-serializer: org.springframework.kafka.support.serializer.JsonSerializer

server:
  port: ${SERVER_PORT:8082}
  

// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/SubscriptionCommandServiceApplication.java
package com.ktds.subs.subscription.command;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SubscriptionCommandServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(SubscriptionCommandServiceApplication.class, args);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/dto/response/SubscriptionResponse.java
package com.ktds.subs.subscription.command.dto.response;

import com.ktds.subs.subscription.command.domain.Subscription;
import lombok.Getter;
import lombok.Builder;

import java.time.LocalDateTime;

@Getter
@Builder
public class SubscriptionResponse {
    private Long subscriptionId;
    private String serviceName;
    private String category;
    private Long paymentAmount;
    private String paymentCycle;
    private Integer paymentDay;
    private LocalDateTime startDate;
    private LocalDateTime lastPaymentDate;
    private LocalDateTime nextPaymentDate;
    
    public static SubscriptionResponse from(Subscription subscription) {
        return SubscriptionResponse.builder()
            .subscriptionId(subscription.getSubscriptionId())
            .serviceName(subscription.getServiceName())
            .category(subscription.getCategory())
            .paymentAmount(subscription.getPaymentAmount())
            .paymentCycle(subscription.getPaymentCycle())
            .paymentDay(subscription.getPaymentDay())
            .startDate(subscription.getStartDate())
            .lastPaymentDate(subscription.getLastPaymentDate())
            .nextPaymentDate(subscription.getNextPaymentDate())
            .build();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/dto/response/DeleteResponse.java
package com.ktds.subs.subscription.command.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import java.time.LocalDateTime;

@Getter
@AllArgsConstructor
public class DeleteResponse {
    private String status;
    private String message;
    private LocalDateTime deletedAt;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/dto/request/SubscriptionCreateRequest.java
package com.ktds.subs.subscription.command.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.Getter;

@Getter
public class SubscriptionCreateRequest {
    @NotBlank(message = "서비스명은 필수입니다.")
    private String serviceName;
    
    @NotBlank(message = "카테고리는 필수입니다.")
    private String category;
    
    @NotNull(message = "결제금액은 필수입니다.")
    @Positive(message = "결제금액은 양수여야 합니다.")
    private Long paymentAmount;
    
    @NotBlank(message = "결제주기는 필수입니다.")
    private String paymentCycle;
    
    @NotNull(message = "결제일은 필수입니다.")
    private Integer paymentDay;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/dto/request/SubscriptionUpdateRequest.java
package com.ktds.subs.subscription.command.dto.request;

import jakarta.validation.constraints.Positive;
import lombok.Getter;

@Getter
public class SubscriptionUpdateRequest {
    @Positive(message = "결제금액은 양수여야 합니다.")
    private Long paymentAmount;
    
    private String paymentCycle;
    private Integer paymentDay;
    private String category;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/repository/SubscriptionCommandRepository.java
package com.ktds.subs.subscription.command.repository;

import com.ktds.subs.subscription.command.domain.Subscription;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SubscriptionCommandRepository extends JpaRepository<Subscription, Long> {
    boolean existsByUserIdAndServiceNameAndDeletedAtIsNull(String userId, String serviceName);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/config/KafkaConfig.java
package com.ktds.subs.subscription.command.config;

import com.ktds.subs.subscription.command.event.SubscriptionEvent;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;
import org.springframework.kafka.support.serializer.JsonSerializer;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class KafkaConfig {

    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;

    @Bean
    public ProducerFactory<String, SubscriptionEvent> producerFactory() {
        Map<String, Object> configs = new HashMap<>();
        configs.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        configs.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        configs.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);
        return new DefaultKafkaProducerFactory<>(configs);
    }

    @Bean
    public KafkaTemplate<String, SubscriptionEvent> kafkaTemplate() {
        return new KafkaTemplate<>(producerFactory());
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/controller/SubscriptionCommandController.java
package com.ktds.subs.subscription.command.controller;

import com.ktds.subs.common.dto.ApiResponse;
import com.ktds.subs.subscription.command.dto.request.SubscriptionCreateRequest;
import com.ktds.subs.subscription.command.dto.request.SubscriptionUpdateRequest;
import com.ktds.subs.subscription.command.service.SubscriptionCommandService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@Tag(name = "구독 관리", description = "구독 서비스 Command API")
@RestController
@RequestMapping("/api/subscriptions")
@RequiredArgsConstructor
public class SubscriptionCommandController {

    private final SubscriptionCommandService subscriptionCommandService;

    @Operation(summary = "구독 서비스 등록", description = "새로운 구독 서비스를 등록합니다.")
    @PostMapping
    public ApiResponse<?> createSubscription(
            @RequestHeader("X-User-ID") String userId,
            @RequestBody SubscriptionCreateRequest request) {
        return ApiResponse.success(subscriptionCommandService.createSubscription(userId, request));
    }

    @Operation(summary = "구독 서비스 수정", description = "기존 구독 서비스 정보를 수정합니다.")
    @PutMapping("/{subscriptionId}")
    public ApiResponse<?> updateSubscription(
            @RequestHeader("X-User-ID") String userId,
            @PathVariable Long subscriptionId,
            @RequestBody SubscriptionUpdateRequest request) {
        return ApiResponse.success(subscriptionCommandService.updateSubscription(userId, subscriptionId, request));
    }

    @Operation(summary = "구독 서비스 삭제", description = "구독 서비스를 삭제합니다.")
    @DeleteMapping("/{subscriptionId}")
    public ApiResponse<?> deleteSubscription(
            @RequestHeader("X-User-ID") String userId,
            @PathVariable Long subscriptionId) {
        return ApiResponse.success(subscriptionCommandService.deleteSubscription(userId, subscriptionId));
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/service/SubscriptionCommandService.java
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


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/service/impl/SubscriptionCommandServiceImpl.java
package com.ktds.subs.subscription.command.service.impl;

import com.ktds.subs.subscription.command.domain.Subscription;
import com.ktds.subs.subscription.command.dto.request.SubscriptionCreateRequest;
import com.ktds.subs.subscription.command.dto.request.SubscriptionUpdateRequest;
import com.ktds.subs.subscription.command.dto.response.DeleteResponse;
import com.ktds.subs.subscription.command.dto.response.SubscriptionResponse;
import com.ktds.subs.subscription.command.event.SubscriptionEvent;
import com.ktds.subs.subscription.command.repository.SubscriptionCommandRepository;
import com.ktds.subs.subscription.command.service.SubscriptionCommandService;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class SubscriptionCommandServiceImpl implements SubscriptionCommandService {

    private final SubscriptionCommandRepository subscriptionRepository;
    private final KafkaTemplate<String, SubscriptionEvent> kafkaTemplate;
    private static final String TOPIC = "subscription-events";

    @Override
    @Transactional
    public SubscriptionResponse createSubscription(String userId, SubscriptionCreateRequest request) {
        // 중복 구독 체크
        if (subscriptionRepository.existsByUserIdAndServiceNameAndDeletedAtIsNull(userId, request.getServiceName())) {
            throw new RuntimeException("이미 구독 중인 서비스입니다.");
        }

        // 구독 생성
        Subscription subscription = new Subscription();
        subscription.setUserId(userId);
        subscription.setServiceName(request.getServiceName());
        subscription.setCategory(request.getCategory());
        subscription.setPaymentAmount(request.getPaymentAmount());
        subscription.setPaymentCycle(request.getPaymentCycle());
        subscription.setPaymentDay(request.getPaymentDay());

        Subscription savedSubscription = subscriptionRepository.save(subscription);

        // 이벤트 발행
        publishSubscriptionEvent("SUBSCRIPTION_CREATED", savedSubscription);

        return SubscriptionResponse.from(savedSubscription);
    }

    @Override
    @Transactional
    public SubscriptionResponse updateSubscription(String userId, Long subscriptionId, SubscriptionUpdateRequest request) {
        Subscription subscription = subscriptionRepository.findById(subscriptionId)
            .orElseThrow(() -> new RuntimeException("구독 정보를 찾을 수 없습니다."));

        if (!subscription.getUserId().equals(userId)) {
            throw new RuntimeException("수정 권한이 없습니다.");
        }

        // 구독 정보 업데이트
        subscription.update(request);
        Subscription updatedSubscription = subscriptionRepository.save(subscription);

        // 이벤트 발행
        publishSubscriptionEvent("SUBSCRIPTION_UPDATED", updatedSubscription);

        return SubscriptionResponse.from(updatedSubscription);
    }

    @Override
    @Transactional
    public DeleteResponse deleteSubscription(String userId, Long subscriptionId) {
        Subscription subscription = subscriptionRepository.findById(subscriptionId)
            .orElseThrow(() -> new RuntimeException("구독 정보를 찾을 수 없습니다."));

        if (!subscription.getUserId().equals(userId)) {
            throw new RuntimeException("삭제 권한이 없습니다.");
        }

        subscription.setDeletedAt(LocalDateTime.now());
        subscriptionRepository.save(subscription);

        // 이벤트 발행
        publishSubscriptionEvent("SUBSCRIPTION_DELETED", subscription);

        return new DeleteResponse("SUCCESS", "구독이 삭제되었습니다.", LocalDateTime.now());
    }

    private void publishSubscriptionEvent(String eventType, Subscription subscription) {
        SubscriptionEvent event = SubscriptionEvent.builder()
            .eventType(eventType)
            .subscriptionId(subscription.getSubscriptionId())
            .userId(subscription.getUserId())
            .serviceName(subscription.getServiceName())
            .category(subscription.getCategory())
            .paymentAmount(subscription.getPaymentAmount())
            .paymentCycle(subscription.getPaymentCycle())
            .paymentDay(subscription.getPaymentDay())
            .eventTime(LocalDateTime.now())
            .build();

        kafkaTemplate.send(TOPIC, event);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/domain/Subscription.java
package com.ktds.subs.subscription.command.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "subscriptions")
@Getter
@NoArgsConstructor
public class Subscription {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "subscription_id")
    private Long subscriptionId;
    
    @Column(name = "user_id")
    private String userId;
    
    @Column(name = "service_name")
    private String serviceName;
    
    private String category;
    
    @Column(name = "payment_amount")
    private Long paymentAmount;
    
    @Column(name = "payment_cycle")
    private String paymentCycle;
    
    @Column(name = "payment_day")
    private Integer paymentDay;
    
    @Column(name = "start_date")
    private LocalDateTime startDate;
    
    @Column(name = "last_payment_date")
    private LocalDateTime lastPaymentDate;
    
    @Column(name = "next_payment_date")
    private LocalDateTime nextPaymentDate;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        startDate = LocalDateTime.now();
        calculateNextPaymentDate();
    }
    
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
        calculateNextPaymentDate();
    }
    
    private void calculateNextPaymentDate() {
        // 다음 결제일 계산 로직
        if (lastPaymentDate == null) {
            lastPaymentDate = startDate;
        }
        
        // payment_cycle에 따른 다음 결제일 계산
        switch (paymentCycle.toUpperCase()) {
            case "MONTHLY":
                nextPaymentDate = lastPaymentDate.plusMonths(1);
                break;
            case "YEARLY":
                nextPaymentDate = lastPaymentDate.plusYears(1);
                break;
            default:
                nextPaymentDate = lastPaymentDate.plusMonths(1);
        }
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/event/SubscriptionEvent.java
package com.ktds.subs.subscription.command.event;

import lombok.Getter;
import lombok.Builder;
import java.time.LocalDateTime;

@Getter
@Builder
public class SubscriptionEvent {
    private String eventType;
    private Long subscriptionId;
    private String userId;
    private String serviceName;
    private String category;
    private Long paymentAmount;
    private String paymentCycle;
    private Integer paymentDay;
    private LocalDateTime eventTime;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/build.gradle
dependencies {
    implementation project(':common')
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-data-mongodb'
    implementation 'org.springframework.kafka:spring-kafka'
    implementation 'org.springframework.boot:spring-boot-starter-cache'
    implementation 'org.springframework.boot:spring-boot-starter-data-redis'
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/resources/application.yml
spring:
  application:
    name: ${SPRING_APPLICATION_NAME:subscription-query-service}
  data:
    mongodb:
      uri: ${MONGODB_URI}
      database: ${MONGODB_DATABASE}
  redis:
    host: ${REDIS_HOST:localhost}
    port: ${REDIS_PORT:6379}
  kafka:
    bootstrap-servers: ${KAFKA_BOOTSTRAP_SERVERS}
    consumer:
      group-id: ${KAFKA_CONSUMER_GROUP_ID:subscription-query-service}
      auto-offset-reset: earliest
      key-deserializer: org.apache.kafka.common.serialization.StringDeserializer
      value-deserializer: org.springframework.kafka.support.serializer.JsonDeserializer

server:
  port: ${SERVER_PORT:8083}
  

// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/SubscriptionQueryServiceApplication.java
package com.ktds.subs.subscription.query;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@EnableCaching
public class SubscriptionQueryServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(SubscriptionQueryServiceApplication.class, args);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/dto/response/DashboardResponse.java
package com.ktds.subs.subscription.query.dto.response;

import lombok.Builder;
import lombok.Getter;
import java.util.List;

@Getter
@Builder
public class DashboardResponse {
    private Long totalAmount;
    private List<SubscriptionSummary> subscriptions;
    
    @Getter
    @Builder
    public static class SubscriptionSummary {
        private Long subscriptionId;
        private String serviceName;
        private String category;
        private Long paymentAmount;
        private String paymentCycle;
        private LocalDateTime nextPaymentDate;
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/dto/response/TotalAmountResponse.java
package com.ktds.subs.subscription.query.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class TotalAmountResponse {
    private Long totalAmount;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/dto/response/PaymentScheduleResponse.java
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


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/repository/SubscriptionViewRepository.java
package com.ktds.subs.subscription.query.repository;

import com.ktds.subs.subscription.query.domain.SubscriptionView;
import org.springframework.data.mongodb.repository.MongoRepository;
import java.util.List;

public interface SubscriptionViewRepository extends MongoRepository<SubscriptionView, Long> {
    List<SubscriptionView> findByUserId(String userId);
    List<SubscriptionView> findByUserIdAndCategory(String userId, String category);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/config/KafkaConfig.java
package com.ktds.subs.subscription.query.config;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.support.serializer.JsonDeserializer;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class KafkaConfig {

    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;

    @Value("${spring.kafka.consumer.group-id}")
    private String groupId;

    @Bean
    public ConsumerFactory<String, Object> consumerFactory() {
        Map<String, Object> configs = new HashMap<>();
        configs.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        configs.put(ConsumerConfig.GROUP_ID_CONFIG, groupId);
        configs.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        configs.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, JsonDeserializer.class);
        configs.put(JsonDeserializer.TRUSTED_PACKAGES, "com.ktds.subs.subscription.*");
        
        return new DefaultKafkaConsumerFactory<>(configs);
    }

    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, Object> kafkaListenerContainerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, Object> factory = 
            new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(consumerFactory());
        return factory;
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/config/RedisConfig.java
package com.ktds.subs.subscription.query.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {

    @Value("${spring.redis.host}")
    private String redisHost;

    @Value("${spring.redis.port}")
    private int redisPort;

    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        return new LettuceConnectionFactory(redisHost, redisPort);
    }

    @Bean
    public RedisTemplate<String, Object> redisTemplate() {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(redisConnectionFactory());
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
        return template;
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/controller/SubscriptionQueryController.java
package com.ktds.subs.subscription.query.controller;

import com.ktds.subs.common.dto.ApiResponse;
import com.ktds.subs.subscription.query.service.SubscriptionQueryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@Tag(name = "구독 조회", description = "구독 서비스 Query API")
@RestController
@RequestMapping("/api/subscriptions")
@RequiredArgsConstructor
public class SubscriptionQueryController {

    private final SubscriptionQueryService subscriptionQueryService;

    @Operation(summary = "구독 대시보드 조회", description = "사용자의 구독 서비스 요약 정보를 조회합니다.")
    @GetMapping("/summary")
    public ApiResponse<?> getDashboard(
            @RequestHeader("X-User-ID") String userId) {
        return ApiResponse.success(subscriptionQueryService.getDashboard(userId));
    }

    @Operation(summary = "카테고리별 구독 조회", description = "카테고리별 구독 서비스 목록을 조회합니다.")
    @GetMapping("/category")
    public ApiResponse<?> getSubscriptionsByCategory(
            @RequestHeader("X-User-ID") String userId,
            @RequestParam String category) {
        return ApiResponse.success(subscriptionQueryService.getSubscriptionsByCategory(userId, category));
    }

    @Operation(summary = "월별 결제일 조회", description = "특정 월의 결제 일정을 조회합니다.")
    @GetMapping("/calendar")
    public ApiResponse<?> getPaymentSchedule(
            @RequestHeader("X-User-ID") String userId,
            @RequestParam String yearMonth) {
        return ApiResponse.success(subscriptionQueryService.getPaymentSchedule(userId, yearMonth));
    }

    @Operation(summary = "월별 총액 조회", description = "특정 월의 총 결제 금액을 조회합니다.")
    @GetMapping("/total")
    public ApiResponse<?> getTotalAmount(
            @RequestHeader("X-User-ID") String userId,
            @RequestParam String yearMonth) {
        return ApiResponse.success(subscriptionQueryService.getTotalAmount(userId, yearMonth));
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/service/SubscriptionQueryService.java
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


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/service/impl/SubscriptionQueryServiceImpl.java
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


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/domain/SubscriptionView.java
package com.ktds.subs.subscription.query.domain;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import java.time.LocalDateTime;

@Document(collection = "subscription_views")
@Getter
@Setter
public class SubscriptionView {
    @Id
    private Long subscriptionId;
    
    private String userId;
    private String serviceName;
    private String category;
    private Long paymentAmount;
    private String paymentCycle;
    private Integer paymentDay;
    private LocalDateTime startDate;
    private LocalDateTime lastPaymentDate;
    private LocalDateTime nextPaymentDate;
    private Integer totalPayments;
    private Long totalAmount;
    private Double avgMonthlyAmount;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/event/SubscriptionEventListener.java
package com.ktds.subs.subscription.query.event;

import com.ktds.subs.subscription.query.domain.SubscriptionView;
import com.ktds.subs.subscription.query.repository.SubscriptionViewRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SubscriptionEventListener {

    private final SubscriptionViewRepository subscriptionViewRepository;

    @KafkaListener(topics = "subscription-events", groupId = "${spring.kafka.consumer.group-id}")
    public void handleSubscriptionEvent(SubscriptionEvent event) {
        switch (event.getEventType()) {
            case "SUBSCRIPTION_CREATED":
                handleSubscriptionCreated(event);
                break;
            case "SUBSCRIPTION_UPDATED":
                handleSubscriptionUpdated(event);
                break;
            case "SUBSCRIPTION_DELETED":
                handleSubscriptionDeleted(event);
                break;
        }
    }

    private void handleSubscriptionCreated(SubscriptionEvent event) {
        SubscriptionView view = new SubscriptionView();
        updateSubscriptionView(view, event);
        subscriptionViewRepository.save(view);
    }

    private void handleSubscriptionUpdated(SubscriptionEvent event) {
        subscriptionViewRepository.findById(event.getSubscriptionId())
            .ifPresent(view -> {
                updateSubscriptionView(view, event);
                subscriptionViewRepository.save(view);
            });
    }

    private void handleSubscriptionDeleted(SubscriptionEvent event) {
        subscriptionViewRepository.deleteById(event.getSubscriptionId());
    }

    private void updateSubscriptionView(SubscriptionView view, SubscriptionEvent event) {
        view.setSubscriptionId(event.getSubscriptionId());
        view.setUserId(event.getUserId());
        view.setServiceName(event.getServiceName());
        view.setCategory(event.getCategory());
        view.setPaymentAmount(event.getPaymentAmount());
        view.setPaymentCycle(event.getPaymentCycle());
        view.setPaymentDay(event.getPaymentDay());
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/build.gradle
dependencies {
    implementation project(':common')
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    implementation 'org.springframework.boot:spring-boot-starter-security'
    implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
    runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.5'
    runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.11.5'
    implementation 'mysql:mysql-connector-java:8.0.33'
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/resources/application.yml
spring:
  application:
    name: ${SPRING_APPLICATION_NAME:auth-service}
  datasource:
    url: ${DATASOURCE_URL}
    username: ${DATASOURCE_USERNAME}
    password: ${DATASOURCE_PASSWORD}
    driver-class-name: com.mysql.cj.jdbc.Driver
  jpa:
    hibernate:
      ddl-auto: validate
    properties:
      hibernate:
        format_sql: true
        show_sql: true

server:
  port: ${SERVER_PORT:8081}

jwt:
  secret: ${JWT_SECRET}
  access-token-validity: ${JWT_ACCESS_TOKEN_VALIDITY:3600000}

oauth2:
  google:
    client-id: ${GOOGLE_CLIENT_ID}
    client-secret: ${GOOGLE_CLIENT_SECRET}
    token-uri: https://oauth2.googleapis.com/token
    user-info-uri: https://www.googleapis.com/oauth2/v3/userinfo
    
    

// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/AuthServiceApplication.java
package com.ktds.subs.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/dto/GoogleUserInfo.java
package com.ktds.subs.auth.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class GoogleUserInfo {
    private String id;
    private String email;
    private String name;
    private String picture;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/dto/response/UserProfileResponse.java
package com.ktds.subs.auth.dto.response;

import com.ktds.subs.auth.domain.User;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class UserProfileResponse {
    private String userId;
    private String nickname;
    private String gender;

    public static UserProfileResponse from(User user) {
        return UserProfileResponse.builder()
            .userId(user.getUserId())
            .nickname(user.getNickname())
            .gender(user.getGender())
            .build();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/dto/response/NotificationSettingResponse.java
package com.ktds.subs.auth.dto.response;

import com.ktds.subs.auth.domain.User;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class NotificationSettingResponse {
    private boolean enabled;

    public static NotificationSettingResponse from(User user) {
        return NotificationSettingResponse.builder()
            .enabled(user.isNotificationEnabled())
            .build();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/dto/response/TokenResponse.java
package com.ktds.subs.auth.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class TokenResponse {
    private String accessToken;
    private String refreshToken;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/dto/request/SocialLoginRequest.java
package com.ktds.subs.auth.dto.request;

import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class SocialLoginRequest {
    private String provider;
    private String code;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/repository/TokenRepository.java
package com.ktds.subs.auth.repository;

import com.ktds.subs.auth.domain.Token;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByRefreshToken(String refreshToken);
    void deleteByUserId(String userId);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/repository/UserRepository.java
package com.ktds.subs.auth.repository;

import com.ktds.subs.auth.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findByProviderAndProviderUserId(String provider, String providerUserId);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/util/JwtTokenProvider.java
package com.ktds.subs.auth.util;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.UUID;

@Component
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.access-token-validity}")
    private long accessTokenValidityInMilliseconds;

    public String createAccessToken(String userId) {
        Claims claims = Jwts.claims().setSubject(userId);
        Date now = new Date();
        Date validity = new Date(now.getTime() + accessTokenValidityInMilliseconds);

        return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(validity)
            .signWith(SignatureAlgorithm.HS256, jwtSecret)
            .compact();
    }

    public String createRefreshToken() {
        return UUID.randomUUID().toString();
    }

    public String getUserId(String token) {
        return Jwts.parser()
            .setSigningKey(jwtSecret)
            .parseClaimsJws(token)
            .getBody()
            .getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/config/SecurityConfig.java
package com.ktds.subs.auth.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authorizeRequests()
            .requestMatchers("/api/auth/**").permitAll()
            .anyRequest().authenticated();
            
        return http.build();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/config/SwaggerConfig.java
package com.ktds.subs.auth.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {
    
    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("인증 서비스 API")
                .description("구독 관리 서비스의 인증 관련 API입니다.")
                .version("1.0"));
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/controller/AuthController.java
package com.ktds.subs.auth.controller;

import com.ktds.subs.auth.dto.request.SocialLoginRequest;
import com.ktds.subs.auth.dto.response.TokenResponse;
import com.ktds.subs.auth.service.AuthService;
import com.ktds.subs.common.dto.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@Tag(name = "인증", description = "인증 관련 API")
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    
    private final AuthService authService;
    
    @Operation(summary = "소셜 로그인", description = "소셜 계정으로 로그인합니다.")
    @PostMapping("/login")
    public ApiResponse<TokenResponse> login(@RequestBody SocialLoginRequest request) {
        return ApiResponse.success(authService.login(request.getProvider(), request.getCode()));
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/controller/UserController.java
package com.ktds.subs.auth.controller;

import com.ktds.subs.auth.service.UserService;
import com.ktds.subs.common.dto.ApiResponse;
import com.ktds.subs.auth.dto.request.UserProfileRequest;
import com.ktds.subs.auth.dto.request.NotificationSettingRequest;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@Tag(name = "사용자", description = "사용자 관련 API")
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @Operation(summary = "프로필 조회", description = "사용자 프로필을 조회합니다.")
    @GetMapping("/{userId}")
    public ApiResponse<?> getProfile(@PathVariable String userId) {
        return ApiResponse.success(userService.getProfile(userId));
    }

    @Operation(summary = "프로필 수정", description = "사용자 프로필을 수정합니다.")
    @PutMapping("/{userId}")
    public ApiResponse<?> updateProfile(
            @PathVariable String userId,
            @RequestBody UserProfileRequest request) {
        return ApiResponse.success(userService.updateProfile(userId, request));
    }

    @Operation(summary = "알림 설정 조회", description = "사용자의 알림 설정을 조회합니다.")
    @GetMapping("/{userId}/notifications")
    public ApiResponse<?> getNotificationSettings(@PathVariable String userId) {
        return ApiResponse.success(userService.getNotificationSettings(userId));
    }

    @Operation(summary = "알림 설정 수정", description = "사용자의 알림 설정을 수정합니다.")
    @PutMapping("/{userId}/notifications")
    public ApiResponse<?> updateNotificationSettings(
            @PathVariable String userId,
            @RequestBody NotificationSettingRequest request) {
        return ApiResponse.success(userService.updateNotificationSettings(userId, request));
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/service/UserService.java
package com.ktds.subs.auth.service;

import com.ktds.subs.auth.dto.request.UserProfileRequest;
import com.ktds.subs.auth.dto.request.NotificationSettingRequest;
import com.ktds.subs.auth.dto.response.UserProfileResponse;
import com.ktds.subs.auth.dto.response.NotificationSettingResponse;

public interface UserService {
    UserProfileResponse getProfile(String userId);
    UserProfileResponse updateProfile(String userId, UserProfileRequest request);
    NotificationSettingResponse getNotificationSettings(String userId);
    NotificationSettingResponse updateNotificationSettings(String userId, NotificationSettingRequest request);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/service/AuthService.java
package com.ktds.subs.auth.service;

import com.ktds.subs.auth.dto.response.TokenResponse;

public interface AuthService {
    TokenResponse login(String provider, String code);
    TokenResponse refresh(String refreshToken);
    void logout(String refreshToken);
    TokenResponse signup(String provider, String code);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/service/impl/UserServiceImpl.java
package com.ktds.subs.auth.service.impl;

import com.ktds.subs.auth.domain.User;
import com.ktds.subs.auth.dto.request.UserProfileRequest;
import com.ktds.subs.auth.dto.request.NotificationSettingRequest;
import com.ktds.subs.auth.dto.response.UserProfileResponse;
import com.ktds.subs.auth.dto.response.NotificationSettingResponse;
import com.ktds.subs.auth.repository.UserRepository;
import com.ktds.subs.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserProfileResponse getProfile(String userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        return UserProfileResponse.from(user);
    }

    @Override
    @Transactional
    public UserProfileResponse updateProfile(String userId, UserProfileRequest request) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        
        user.setNickname(request.getNickname());
        user.setGender(request.getGender());
        
        return UserProfileResponse.from(userRepository.save(user));
    }

    @Override
    @Transactional(readOnly = true)
    public NotificationSettingResponse getNotificationSettings(String userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        return NotificationSettingResponse.from(user);
    }

    @Override
    @Transactional
    public NotificationSettingResponse updateNotificationSettings(String userId, NotificationSettingRequest request) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        
        user.setNotificationEnabled(request.isEnabled());
        
        return NotificationSettingResponse.from(userRepository.save(user));
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/service/impl/AuthServiceImpl.java
package com.ktds.subs.auth.service.impl;

import com.ktds.subs.auth.domain.Token;
import com.ktds.subs.auth.domain.User;
import com.ktds.subs.auth.dto.response.TokenResponse;
import com.ktds.subs.auth.repository.TokenRepository;
import com.ktds.subs.auth.repository.UserRepository;
import com.ktds.subs.auth.service.AuthService;
import com.ktds.subs.auth.util.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final GoogleOAuthClient googleOAuthClient;

    @Override
    @Transactional
    public TokenResponse login(String provider, String code) {
        // 구글 OAuth로 사용자 정보 조회
        GoogleUserInfo userInfo = googleOAuthClient.getUserInfo(code);
        
        // 기존 사용자 조회 또는 새로운 사용자 생성
        User user = userRepository.findByProviderAndProviderUserId(provider, userInfo.getId())
            .orElseGet(() -> signup(provider, userInfo));

        // 토큰 생성
        String accessToken = jwtTokenProvider.createAccessToken(user.getUserId());
        String refreshToken = jwtTokenProvider.createRefreshToken();

        // Refresh 토큰 저장
        saveRefreshToken(user.getUserId(), refreshToken);

        return new TokenResponse(accessToken, refreshToken);
    }

    @Override
    @Transactional
    public TokenResponse refresh(String refreshToken) {
        // Refresh 토큰 검증
        Token token = tokenRepository.findByRefreshToken(refreshToken)
            .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        // 새로운 액세스 토큰 발급
        String newAccessToken = jwtTokenProvider.createAccessToken(token.getUserId());

        return new TokenResponse(newAccessToken, refreshToken);
    }

    @Override
    @Transactional
    public void logout(String refreshToken) {
        Token token = tokenRepository.findByRefreshToken(refreshToken)
            .orElseThrow(() -> new RuntimeException("Invalid refresh token"));
        tokenRepository.delete(token);
    }

    private User signup(String provider, GoogleUserInfo userInfo) {
        User user = new User();
        user.setUserId(UUID.randomUUID().toString());
        user.setProvider(provider);
        user.setProviderUserId(userInfo.getId());
        user.setNickname(userInfo.getName());
        return userRepository.save(user);
    }

    private void saveRefreshToken(String userId, String refreshToken) {
        Token token = new Token();
        token.setUserId(userId);
        token.setRefreshToken(refreshToken);
        token.setExpiresAt(LocalDateTime.now().plusDays(14));
        tokenRepository.save(token);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/domain/User.java
package com.ktds.subs.auth.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Getter
@NoArgsConstructor
public class User {
    @Id
    @Column(name = "user_id")
    private String userId;
    
    private String nickname;
    
    private String gender;
    
    private String provider;
    
    @Column(name = "provider_user_id")
    private String providerUserId;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
    
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/domain/Token.java
package com.ktds.subs.auth.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "refresh_tokens")
@Getter
@NoArgsConstructor
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "token_id")
    private Long tokenId;
    
    @Column(name = "user_id")
    private String userId;
    
    @Column(name = "refresh_token")
    private String refreshToken;
    
    @Column(name = "expires_at")
    private LocalDateTime expiresAt;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/client/GoogleOAuthClient.java
package com.ktds.subs.auth.client;

import com.ktds.subs.auth.dto.GoogleUserInfo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class GoogleOAuthClient {

    private final RestTemplate restTemplate;
    
    @Value("${oauth2.google.token-uri}")
    private String tokenUri;
    
    @Value("${oauth2.google.user-info-uri}")
    private String userInfoUri;

    public GoogleOAuthClient() {
        this.restTemplate = new RestTemplate();
    }

    public GoogleUserInfo getUserInfo(String code) {
        // 1. 인증 코드로 액세스 토큰 요청
        String accessToken = getAccessToken(code);
        
        // 2. 액세스 토큰으로 사용자 정보 요청
        return getUserInfoWithToken(accessToken);
    }

    private String getAccessToken(String code) {
        // OAuth 토큰 요청 로직 구현
        return "access_token";
    }

    private GoogleUserInfo getUserInfoWithToken(String accessToken) {
        // 사용자 정보 요청 로직 구현
        return new GoogleUserInfo();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/MergedSource.java
// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/settings.gradle
rootProject.name = 'subs-mgmt'

include 'common'
include 'auth-service'
include 'subscription-command-service'
include 'subscription-query-service'
include 'notification-service'
include 'api-gateway'


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/build.gradle
dependencies {
    implementation project(':common')
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    implementation 'org.springframework.kafka:spring-kafka'
    implementation 'com.google.firebase:firebase-admin:9.2.0'
    implementation 'mysql:mysql-connector-java:8.0.33'
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/resources/application.yml
spring:
  application:
    name: ${SPRING_APPLICATION_NAME:notification-service}
  datasource:
    url: ${DATASOURCE_URL}
    username: ${DATASOURCE_USERNAME}
    password: ${DATASOURCE_PASSWORD}
    driver-class-name: com.mysql.cj.jdbc.Driver
  jpa:
    hibernate:
      ddl-auto: validate
    properties:
      hibernate:
        format_sql: true
        show_sql: true
  kafka:
    bootstrap-servers: ${KAFKA_BOOTSTRAP_SERVERS}
    consumer:
      group-id: ${KAFKA_CONSUMER_GROUP_ID:notification-service}
      auto-offset-reset: earliest

server:
  port: ${SERVER_PORT:8084}

firebase:
  config:
    path: ${FIREBASE_CONFIG_PATH:firebase-service-account.json}
    

// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/NotificationServiceApplication.java
package com.ktds.subs.notification;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class NotificationServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(NotificationServiceApplication.class, args);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/dto/response/TokenRegistrationResponse.java
package com.ktds.subs.notification.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import java.time.LocalDateTime;

@Getter
@AllArgsConstructor
public class TokenRegistrationResponse {
    private String status;
    private String message;
    private LocalDateTime registeredAt;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/dto/request/FCMTokenRequest.java
package com.ktds.subs.notification.dto.request;

import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class FCMTokenRequest {
    private String token;
    private String deviceInfo;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/repository/NotificationHistoryRepository.java
package com.ktds.subs.notification.repository;

import com.ktds.subs.notification.domain.NotificationHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface NotificationHistoryRepository extends JpaRepository<NotificationHistory, Long> {
    List<NotificationHistory> findByUserIdOrderBySentAtDesc(String userId);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/repository/FCMTokenRepository.java
package com.ktds.subs.notification.repository;

import com.ktds.subs.notification.domain.FCMToken;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface FCMTokenRepository extends JpaRepository<FCMToken, Long> {
    List<FCMToken> findByUserId(String userId);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/repository/NotificationSettingRepository.java
package com.ktds.subs.notification.repository;

import com.ktds.subs.notification.domain.NotificationSetting;
import org.springframework.data.jpa.repository.JpaRepository;

public interface NotificationSettingRepository extends JpaRepository<NotificationSetting, String> {
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/config/KafkaConfig.java
package com.ktds.subs.notification.config;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.support.serializer.JsonDeserializer;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class KafkaConfig {

    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;

    @Value("${spring.kafka.consumer.group-id}")
    private String groupId;

    @Bean
    public ConsumerFactory<String, Object> consumerFactory() {
        Map<String, Object> props = new HashMap<>();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ConsumerConfig.GROUP_ID_CONFIG, groupId);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, JsonDeserializer.class);
        props.put(JsonDeserializer.TRUSTED_PACKAGES, "*");
        
        return new DefaultKafkaConsumerFactory<>(props);
    }

    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, Object> kafkaListenerContainerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, Object> factory = 
            new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(consumerFactory());
        return factory;
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/config/FirebaseConfig.java
package com.ktds.subs.notification.config;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.messaging.FirebaseMessaging;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;

@Configuration
public class FirebaseConfig {

    @Value("${firebase.config.path}")
    private String firebaseConfigPath;

    @Bean
    public FirebaseMessaging firebaseMessaging() throws IOException {
        GoogleCredentials googleCredentials = GoogleCredentials
            .fromStream(new ClassPathResource(firebaseConfigPath).getInputStream());

        FirebaseOptions firebaseOptions = FirebaseOptions.builder()
            .setCredentials(googleCredentials)
            .build();

        FirebaseApp app = FirebaseApp.initializeApp(firebaseOptions);
        return FirebaseMessaging.getInstance(app);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/controller/NotificationController.java
package com.ktds.subs.notification.controller;

import com.ktds.subs.common.dto.ApiResponse;
import com.ktds.subs.notification.dto.request.FCMTokenRequest;
import com.ktds.subs.notification.service.NotificationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@Tag(name = "알림", description = "알림 관련 API")
@RestController
@RequestMapping("/api/notifications")
@RequiredArgsConstructor
public class NotificationController {

    private final NotificationService notificationService;

    @Operation(summary = "FCM 토큰 등록", description = "사용자의 FCM 토큰을 등록합니다.")
    @PostMapping("/token")
    public ApiResponse<?> registerToken(
            @RequestHeader("X-User-ID") String userId,
            @RequestBody FCMTokenRequest request) {
        return ApiResponse.success(notificationService.registerToken(userId, request));
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/service/FirebaseMessagingService.java
package com.ktds.subs.notification.service;

import com.google.firebase.messaging.FirebaseMessaging;
import com.google.firebase.messaging.Message;
import com.google.firebase.messaging.Notification;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class FirebaseMessagingService {

    private final FirebaseMessaging firebaseMessaging;

    public void sendMessage(String token, String title, String body) throws Exception {
        Message message = Message.builder()
            .setNotification(Notification.builder()
                .setTitle(title)
                .setBody(body)
                .build())
            .setToken(token)
            .build();

        firebaseMessaging.send(message);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/service/NotificationService.java
package com.ktds.subs.notification.service;

import com.ktds.subs.notification.dto.request.FCMTokenRequest;
import com.ktds.subs.notification.dto.response.TokenRegistrationResponse;
import com.ktds.subs.subscription.command.event.SubscriptionEvent;

public interface NotificationService {
    TokenRegistrationResponse registerToken(String userId, FCMTokenRequest request);
    void handleSubscriptionEvent(SubscriptionEvent event);
    void sendPaymentNotification(String userId, Long subscriptionId, String serviceName, Long paymentAmount);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/service/impl/NotificationServiceImpl.java
package com.ktds.subs.notification.service.impl;

import com.ktds.subs.notification.domain.FCMToken;
import com.ktds.subs.notification.domain.NotificationHistory;
import com.ktds.subs.notification.domain.NotificationSetting;
import com.ktds.subs.notification.dto.request.FCMTokenRequest;
import com.ktds.subs.notification.dto.response.TokenRegistrationResponse;
import com.ktds.subs.notification.repository.FCMTokenRepository;
import com.ktds.subs.notification.repository.NotificationHistoryRepository;
import com.ktds.subs.notification.repository.NotificationSettingRepository;
import com.ktds.subs.notification.service.NotificationService;
import com.ktds.subs.subscription.command.event.SubscriptionEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class NotificationServiceImpl implements NotificationService {

    private final FCMTokenRepository fcmTokenRepository;
    private final NotificationSettingRepository notificationSettingRepository;
    private final NotificationHistoryRepository notificationHistoryRepository;
    private final FirebaseMessagingService firebaseMessagingService;

    @Override
    @Transactional
    public TokenRegistrationResponse registerToken(String userId, FCMTokenRequest request) {
        FCMToken fcmToken = new FCMToken();
        fcmToken.setUserId(userId);
        fcmToken.setFcmToken(request.getToken());
        fcmToken.setDeviceInfo(request.getDeviceInfo());
        fcmTokenRepository.save(fcmToken);

        return new TokenRegistrationResponse(
            "SUCCESS",
            "FCM 토큰이 등록되었습니다.",
            LocalDateTime.now()
        );
    }

    @Override
    @Transactional
    public void handleSubscriptionEvent(SubscriptionEvent event) {
        switch (event.getEventType()) {
            case "SUBSCRIPTION_CREATED":
                sendWelcomeNotification(event);
                break;
            case "SUBSCRIPTION_UPDATED":
                sendUpdateNotification(event);
                break;
            case "SUBSCRIPTION_DELETED":
                sendDeleteNotification(event);
                break;
        }
    }

    @Override
    @Transactional
    public void sendPaymentNotification(String userId, Long subscriptionId, String serviceName, Long paymentAmount) {
        NotificationSetting setting = notificationSettingRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("알림 설정을 찾을 수 없습니다."));

        if (!setting.isPaymentNotification()) {
            return;
        }

        List<FCMToken> tokens = fcmTokenRepository.findByUserId(userId);
        String title = "결제 예정 알림";
        String message = String.format("%s 서비스의 결제(%,d원)가 예정되어 있습니다.", serviceName, paymentAmount);

        tokens.forEach(token -> {
            try {
                firebaseMessagingService.sendMessage(token.getFcmToken(), title, message);
                saveNotificationHistory(userId, subscriptionId, "PAYMENT", title, message);
            } catch (Exception e) {
                // 토큰이 만료되었거나 유효하지 않은 경우 처리
                fcmTokenRepository.delete(token);
            }
        });
    }

    private void sendWelcomeNotification(SubscriptionEvent event) {
        String title = "구독 서비스 등록";
        String message = String.format("%s 서비스가 등록되었습니다.", event.getServiceName());
        sendNotification(event.getUserId(), event.getSubscriptionId(), "WELCOME", title, message);
    }

    private void sendUpdateNotification(SubscriptionEvent event) {
        String title = "구독 서비스 수정";
        String message = String.format("%s 서비스 정보가 수정되었습니다.", event.getServiceName());
        sendNotification(event.getUserId(), event.getSubscriptionId(), "UPDATE", title, message);
    }

    private void sendDeleteNotification(SubscriptionEvent event) {
        String title = "구독 서비스 삭제";
        String message = String.format("%s 서비스가 삭제되었습니다.", event.getServiceName());
        sendNotification(event.getUserId(), event.getSubscriptionId(), "DELETE", title, message);
    }

    private void sendNotification(String userId, Long subscriptionId, String type, String title, String message) {
        List<FCMToken> tokens = fcmTokenRepository.findByUserId(userId);
        tokens.forEach(token -> {
            try {
                firebaseMessagingService.sendMessage(token.getFcmToken(), title, message);
                saveNotificationHistory(userId, subscriptionId, type, title, message);
            } catch (Exception e) {
                fcmTokenRepository.delete(token);
            }
        });
    }

    private void saveNotificationHistory(String userId, Long subscriptionId, String type, String title, String message) {
        NotificationHistory history = new NotificationHistory();
        history.setUserId(userId);
        history.setSubscriptionId(subscriptionId);
        history.setNotificationType(type);
        history.setTitle(title);
        history.setMessage(message);
        history.setSentAt(LocalDateTime.now());
        notificationHistoryRepository.save(history);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/domain/NotificationHistory.java
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


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/domain/NotificationSetting.java
package com.ktds.subs.notification.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;
import java.time.LocalTime;

@Entity
@Table(name = "notification_settings")
@Getter
@NoArgsConstructor
public class NotificationSetting {
    @Id
    @Column(name = "user_id")
    private String userId;
    
    @Column(name = "payment_notification")
    private boolean paymentNotification;
    
    @Column(name = "notification_time")
    private LocalTime notificationTime;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
    
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/domain/FCMToken.java
package com.ktds.subs.notification.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "fcm_tokens")
@Getter
@NoArgsConstructor
public class FCMToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "token_id")
    private Long tokenId;
    
    @Column(name = "user_id")
    private String userId;
    
    @Column(name = "fcm_token")
    private String fcmToken;
    
    @Column(name = "device_info")
    private String deviceInfo;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/event/SubscriptionEventListener.java
package com.ktds.subs.notification.event;

import com.ktds.subs.notification.service.NotificationService;
import com.ktds.subs.subscription.command.event.SubscriptionEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SubscriptionEventListener {

    private final NotificationService notificationService;

    @KafkaListener(topics = "subscription-events", groupId = "${spring.kafka.consumer.group-id}")
    public void handleSubscriptionEvent(SubscriptionEvent event) {
        notificationService.handleSubscriptionEvent(event);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/api-gateway/build.gradle
dependencies {
    implementation 'org.springframework.cloud:spring-cloud-starter-gateway'
    implementation 'org.springframework.cloud:spring-cloud-starter-netflix-eureka-client'
    implementation 'org.springframework.boot:spring-boot-starter-security'
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/api-gateway/src/main/resources/application.yml
spring:
  application:
    name: ${SPRING_APPLICATION_NAME:api-gateway}
  cloud:
    gateway:
      routes:
        - id: auth-service
          uri: lb://auth-service
          predicates:
            - Path=/api/auth/**
          filters:
            - RewritePath=/api/auth/(?<segment>.*), /api/auth/${segment}

        - id: subscription-command-service
          uri: lb://subscription-command-service
          predicates:
            - Path=/api/subscriptions/**
            - Method=POST,PUT,DELETE
          filters:
            - RewritePath=/api/subscriptions/(?<segment>.*), /api/subscriptions/${segment}

        - id: subscription-query-service
          uri: lb://subscription-query-service
          predicates:
            - Path=/api/subscriptions/**
            - Method=GET
          filters:
            - RewritePath=/api/subscriptions/(?<segment>.*), /api/subscriptions/${segment}

        - id: notification-service
          uri: lb://notification-service
          predicates:
            - Path=/api/notifications/**
          filters:
            - RewritePath=/api/notifications/(?<segment>.*), /api/notifications/${segment}

  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: ${JWT_JWK_SET_URI}

server:
  port: ${SERVER_PORT:8080}

eureka:
  client:
    service-url:
      defaultZone: ${EUREKA_SERVICE_URL:http://localhost:8761/eureka/}
    fetch-registry: true
    register-with-eureka: true
  instance:
    prefer-ip-address: true

jwt:
  secret: ${JWT_SECRET}

management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics
        


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/api-gateway/src/main/java/com/ktds/subs/gateway/ApiGatewayApplication.java
package com.ktds.subs.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class ApiGatewayApplication {
    public static void main(String[] args) {
        SpringApplication.run(ApiGatewayApplication.class, args);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/api-gateway/src/main/java/com/ktds/subs/gateway/util/JwtTokenProvider.java
package com.ktds.subs.gateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Component
public class JwtTokenProvider {

    private final SecretKey key;

    public JwtTokenProvider(@Value("${jwt.secret}") String secret) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public String getUserId(String token) {
        Claims claims = Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)
            .getBody();
        return claims.getSubject();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/api-gateway/src/main/java/com/ktds/subs/gateway/config/SecurityConfig.java
package com.ktds.subs.gateway.config;

import com.ktds.subs.gateway.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
            .csrf().disable()
            .formLogin().disable()
            .httpBasic().disable()
            .authorizeExchange()
            .pathMatchers("/api/auth/**").permitAll()
            .pathMatchers("/actuator/**").permitAll()
            .anyExchange().authenticated()
            .and()
            .addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
            .build();
    }

    @Bean
    public CorsWebFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList("*"));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(Arrays.asList("*"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return new CorsWebFilter(source);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/api-gateway/src/main/java/com/ktds/subs/gateway/filter/JwtAuthenticationFilter.java
package com.ktds.subs.gateway.filter;

import com.ktds.subs.gateway.util.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        
        // Skip authentication for public endpoints
        if (path.startsWith("/api/auth/") || path.startsWith("/actuator/")) {
            return chain.filter(exchange);
        }

        String token = extractToken(exchange);
        
        if (token == null || !jwtTokenProvider.validateToken(token)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // Add user ID to request header
        String userId = jwtTokenProvider.getUserId(token);
        ServerWebExchange modifiedExchange = exchange.mutate()
            .request(exchange.getRequest().mutate()
                .header("X-User-ID", userId)
                .build())
            .build();

        return chain.filter(modifiedExchange);
    }

    private String extractToken(ServerWebExchange exchange) {
        String bearerToken = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/common/build.gradle
dependencies {
    implementation 'com.fasterxml.jackson.core:jackson-databind'
    implementation 'org.springframework.boot:spring-boot-starter-web'
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/common/src/main/resources/application.yml
server:
  port: ${SERVER_PORT:0}

spring:
  application:
    name: ${SPRING_APPLICATION_NAME}
  
  jpa:
    hibernate:
      ddl-auto: validate
    properties:
      hibernate:
        format_sql: true
        show_sql: true
        
logging:
  level:
    root: INFO
    com.ktds: DEBUG


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/common/src/main/java/com/ktds/subs/common/dto/ApiResponse.java
package com.ktds.subs.common.dto;

import lombok.Getter;
import java.time.LocalDateTime;

@Getter
public class ApiResponse<T> {
    private final String status;
    private final String message;
    private final T data;
    private final LocalDateTime timestamp;

    private ApiResponse(String status, String message, T data) {
        this.status = status;
        this.message = message;
        this.data = data;
        this.timestamp = LocalDateTime.now();
    }

    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>("SUCCESS", null, data);
    }

    public static <T> ApiResponse<T> error(String message) {
        return new ApiResponse<>("ERROR", message, null);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/common/src/main/java/com/ktds/subs/common/constant/ErrorCode.java
package com.ktds.subs.common.constant;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {
    // Common Errors
    INVALID_INPUT_VALUE("C001", "Invalid Input Value"),
    METHOD_NOT_ALLOWED("C002", "Method Not Allowed"),
    ENTITY_NOT_FOUND("C003", "Entity Not Found"),
    INTERNAL_SERVER_ERROR("C004", "Internal Server Error"),
    INVALID_TYPE_VALUE("C005", "Invalid Type Value"),
    ACCESS_DENIED("C006", "Access Denied"),
    
    // Auth Errors
    INVALID_AUTH_TOKEN("A001", "Invalid Auth Token"),
    EXPIRED_AUTH_TOKEN("A002", "Expired Auth Token"),
    UNAUTHORIZED("A003", "Unauthorized"),
    INVALID_SOCIAL_TOKEN("A004", "Invalid Social Token"),
    
    // Subscription Errors
    DUPLICATE_SUBSCRIPTION("S001", "Duplicate Subscription"),
    INVALID_SUBSCRIPTION("S002", "Invalid Subscription"),
    SUBSCRIPTION_NOT_FOUND("S003", "Subscription Not Found"),
    
    // Notification Errors
    NOTIFICATION_SEND_FAILED("N001", "Notification Send Failed"),
    INVALID_FCM_TOKEN("N002", "Invalid FCM Token");

    private final String code;
    private final String message;
}









    
    
    

// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/common/src/main/java/com/ktds/subs/common/exception/BaseException.java
package com.ktds.subs.common.exception;

import lombok.Getter;

@Getter
public class BaseException extends RuntimeException {
    private final String errorCode;
    
    public BaseException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/build.gradle
dependencies {
    implementation project(':common')
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    implementation 'org.springframework.kafka:spring-kafka'
    implementation 'mysql:mysql-connector-java:8.0.33'
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/resources/application.yml
spring:
  application:
    name: ${SPRING_APPLICATION_NAME:subscription-command-service}
  datasource:
    url: ${DATASOURCE_URL}
    username: ${DATASOURCE_USERNAME}
    password: ${DATASOURCE_PASSWORD}
    driver-class-name: com.mysql.cj.jdbc.Driver
  jpa:
    hibernate:
      ddl-auto: validate
    properties:
      hibernate:
        format_sql: true
        show_sql: true
  kafka:
    bootstrap-servers: ${KAFKA_BOOTSTRAP_SERVERS}
    producer:
      key-serializer: org.apache.kafka.common.serialization.StringSerializer
      value-serializer: org.springframework.kafka.support.serializer.JsonSerializer

server:
  port: ${SERVER_PORT:8082}
  

// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/SubscriptionCommandServiceApplication.java
package com.ktds.subs.subscription.command;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SubscriptionCommandServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(SubscriptionCommandServiceApplication.class, args);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/dto/response/SubscriptionResponse.java
package com.ktds.subs.subscription.command.dto.response;

import com.ktds.subs.subscription.command.domain.Subscription;
import lombok.Getter;
import lombok.Builder;

import java.time.LocalDateTime;

@Getter
@Builder
public class SubscriptionResponse {
    private Long subscriptionId;
    private String serviceName;
    private String category;
    private Long paymentAmount;
    private String paymentCycle;
    private Integer paymentDay;
    private LocalDateTime startDate;
    private LocalDateTime lastPaymentDate;
    private LocalDateTime nextPaymentDate;
    
    public static SubscriptionResponse from(Subscription subscription) {
        return SubscriptionResponse.builder()
            .subscriptionId(subscription.getSubscriptionId())
            .serviceName(subscription.getServiceName())
            .category(subscription.getCategory())
            .paymentAmount(subscription.getPaymentAmount())
            .paymentCycle(subscription.getPaymentCycle())
            .paymentDay(subscription.getPaymentDay())
            .startDate(subscription.getStartDate())
            .lastPaymentDate(subscription.getLastPaymentDate())
            .nextPaymentDate(subscription.getNextPaymentDate())
            .build();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/dto/response/DeleteResponse.java
package com.ktds.subs.subscription.command.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import java.time.LocalDateTime;

@Getter
@AllArgsConstructor
public class DeleteResponse {
    private String status;
    private String message;
    private LocalDateTime deletedAt;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/dto/request/SubscriptionCreateRequest.java
package com.ktds.subs.subscription.command.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.Getter;

@Getter
public class SubscriptionCreateRequest {
    @NotBlank(message = "서비스명은 필수입니다.")
    private String serviceName;
    
    @NotBlank(message = "카테고리는 필수입니다.")
    private String category;
    
    @NotNull(message = "결제금액은 필수입니다.")
    @Positive(message = "결제금액은 양수여야 합니다.")
    private Long paymentAmount;
    
    @NotBlank(message = "결제주기는 필수입니다.")
    private String paymentCycle;
    
    @NotNull(message = "결제일은 필수입니다.")
    private Integer paymentDay;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/dto/request/SubscriptionUpdateRequest.java
package com.ktds.subs.subscription.command.dto.request;

import jakarta.validation.constraints.Positive;
import lombok.Getter;

@Getter
public class SubscriptionUpdateRequest {
    @Positive(message = "결제금액은 양수여야 합니다.")
    private Long paymentAmount;
    
    private String paymentCycle;
    private Integer paymentDay;
    private String category;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/repository/SubscriptionCommandRepository.java
package com.ktds.subs.subscription.command.repository;

import com.ktds.subs.subscription.command.domain.Subscription;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SubscriptionCommandRepository extends JpaRepository<Subscription, Long> {
    boolean existsByUserIdAndServiceNameAndDeletedAtIsNull(String userId, String serviceName);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/config/KafkaConfig.java
package com.ktds.subs.subscription.command.config;

import com.ktds.subs.subscription.command.event.SubscriptionEvent;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;
import org.springframework.kafka.support.serializer.JsonSerializer;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class KafkaConfig {

    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;

    @Bean
    public ProducerFactory<String, SubscriptionEvent> producerFactory() {
        Map<String, Object> configs = new HashMap<>();
        configs.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        configs.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        configs.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);
        return new DefaultKafkaProducerFactory<>(configs);
    }

    @Bean
    public KafkaTemplate<String, SubscriptionEvent> kafkaTemplate() {
        return new KafkaTemplate<>(producerFactory());
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/controller/SubscriptionCommandController.java
package com.ktds.subs.subscription.command.controller;

import com.ktds.subs.common.dto.ApiResponse;
import com.ktds.subs.subscription.command.dto.request.SubscriptionCreateRequest;
import com.ktds.subs.subscription.command.dto.request.SubscriptionUpdateRequest;
import com.ktds.subs.subscription.command.service.SubscriptionCommandService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@Tag(name = "구독 관리", description = "구독 서비스 Command API")
@RestController
@RequestMapping("/api/subscriptions")
@RequiredArgsConstructor
public class SubscriptionCommandController {

    private final SubscriptionCommandService subscriptionCommandService;

    @Operation(summary = "구독 서비스 등록", description = "새로운 구독 서비스를 등록합니다.")
    @PostMapping
    public ApiResponse<?> createSubscription(
            @RequestHeader("X-User-ID") String userId,
            @RequestBody SubscriptionCreateRequest request) {
        return ApiResponse.success(subscriptionCommandService.createSubscription(userId, request));
    }

    @Operation(summary = "구독 서비스 수정", description = "기존 구독 서비스 정보를 수정합니다.")
    @PutMapping("/{subscriptionId}")
    public ApiResponse<?> updateSubscription(
            @RequestHeader("X-User-ID") String userId,
            @PathVariable Long subscriptionId,
            @RequestBody SubscriptionUpdateRequest request) {
        return ApiResponse.success(subscriptionCommandService.updateSubscription(userId, subscriptionId, request));
    }

    @Operation(summary = "구독 서비스 삭제", description = "구독 서비스를 삭제합니다.")
    @DeleteMapping("/{subscriptionId}")
    public ApiResponse<?> deleteSubscription(
            @RequestHeader("X-User-ID") String userId,
            @PathVariable Long subscriptionId) {
        return ApiResponse.success(subscriptionCommandService.deleteSubscription(userId, subscriptionId));
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/service/SubscriptionCommandService.java
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


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/service/impl/SubscriptionCommandServiceImpl.java
package com.ktds.subs.subscription.command.service.impl;

import com.ktds.subs.subscription.command.domain.Subscription;
import com.ktds.subs.subscription.command.dto.request.SubscriptionCreateRequest;
import com.ktds.subs.subscription.command.dto.request.SubscriptionUpdateRequest;
import com.ktds.subs.subscription.command.dto.response.DeleteResponse;
import com.ktds.subs.subscription.command.dto.response.SubscriptionResponse;
import com.ktds.subs.subscription.command.event.SubscriptionEvent;
import com.ktds.subs.subscription.command.repository.SubscriptionCommandRepository;
import com.ktds.subs.subscription.command.service.SubscriptionCommandService;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class SubscriptionCommandServiceImpl implements SubscriptionCommandService {

    private final SubscriptionCommandRepository subscriptionRepository;
    private final KafkaTemplate<String, SubscriptionEvent> kafkaTemplate;
    private static final String TOPIC = "subscription-events";

    @Override
    @Transactional
    public SubscriptionResponse createSubscription(String userId, SubscriptionCreateRequest request) {
        // 중복 구독 체크
        if (subscriptionRepository.existsByUserIdAndServiceNameAndDeletedAtIsNull(userId, request.getServiceName())) {
            throw new RuntimeException("이미 구독 중인 서비스입니다.");
        }

        // 구독 생성
        Subscription subscription = new Subscription();
        subscription.setUserId(userId);
        subscription.setServiceName(request.getServiceName());
        subscription.setCategory(request.getCategory());
        subscription.setPaymentAmount(request.getPaymentAmount());
        subscription.setPaymentCycle(request.getPaymentCycle());
        subscription.setPaymentDay(request.getPaymentDay());

        Subscription savedSubscription = subscriptionRepository.save(subscription);

        // 이벤트 발행
        publishSubscriptionEvent("SUBSCRIPTION_CREATED", savedSubscription);

        return SubscriptionResponse.from(savedSubscription);
    }

    @Override
    @Transactional
    public SubscriptionResponse updateSubscription(String userId, Long subscriptionId, SubscriptionUpdateRequest request) {
        Subscription subscription = subscriptionRepository.findById(subscriptionId)
            .orElseThrow(() -> new RuntimeException("구독 정보를 찾을 수 없습니다."));

        if (!subscription.getUserId().equals(userId)) {
            throw new RuntimeException("수정 권한이 없습니다.");
        }

        // 구독 정보 업데이트
        subscription.update(request);
        Subscription updatedSubscription = subscriptionRepository.save(subscription);

        // 이벤트 발행
        publishSubscriptionEvent("SUBSCRIPTION_UPDATED", updatedSubscription);

        return SubscriptionResponse.from(updatedSubscription);
    }

    @Override
    @Transactional
    public DeleteResponse deleteSubscription(String userId, Long subscriptionId) {
        Subscription subscription = subscriptionRepository.findById(subscriptionId)
            .orElseThrow(() -> new RuntimeException("구독 정보를 찾을 수 없습니다."));

        if (!subscription.getUserId().equals(userId)) {
            throw new RuntimeException("삭제 권한이 없습니다.");
        }

        subscription.setDeletedAt(LocalDateTime.now());
        subscriptionRepository.save(subscription);

        // 이벤트 발행
        publishSubscriptionEvent("SUBSCRIPTION_DELETED", subscription);

        return new DeleteResponse("SUCCESS", "구독이 삭제되었습니다.", LocalDateTime.now());
    }

    private void publishSubscriptionEvent(String eventType, Subscription subscription) {
        SubscriptionEvent event = SubscriptionEvent.builder()
            .eventType(eventType)
            .subscriptionId(subscription.getSubscriptionId())
            .userId(subscription.getUserId())
            .serviceName(subscription.getServiceName())
            .category(subscription.getCategory())
            .paymentAmount(subscription.getPaymentAmount())
            .paymentCycle(subscription.getPaymentCycle())
            .paymentDay(subscription.getPaymentDay())
            .eventTime(LocalDateTime.now())
            .build();

        kafkaTemplate.send(TOPIC, event);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/domain/Subscription.java
package com.ktds.subs.subscription.command.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "subscriptions")
@Getter
@NoArgsConstructor
public class Subscription {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "subscription_id")
    private Long subscriptionId;
    
    @Column(name = "user_id")
    private String userId;
    
    @Column(name = "service_name")
    private String serviceName;
    
    private String category;
    
    @Column(name = "payment_amount")
    private Long paymentAmount;
    
    @Column(name = "payment_cycle")
    private String paymentCycle;
    
    @Column(name = "payment_day")
    private Integer paymentDay;
    
    @Column(name = "start_date")
    private LocalDateTime startDate;
    
    @Column(name = "last_payment_date")
    private LocalDateTime lastPaymentDate;
    
    @Column(name = "next_payment_date")
    private LocalDateTime nextPaymentDate;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        startDate = LocalDateTime.now();
        calculateNextPaymentDate();
    }
    
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
        calculateNextPaymentDate();
    }
    
    private void calculateNextPaymentDate() {
        // 다음 결제일 계산 로직
        if (lastPaymentDate == null) {
            lastPaymentDate = startDate;
        }
        
        // payment_cycle에 따른 다음 결제일 계산
        switch (paymentCycle.toUpperCase()) {
            case "MONTHLY":
                nextPaymentDate = lastPaymentDate.plusMonths(1);
                break;
            case "YEARLY":
                nextPaymentDate = lastPaymentDate.plusYears(1);
                break;
            default:
                nextPaymentDate = lastPaymentDate.plusMonths(1);
        }
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/event/SubscriptionEvent.java
package com.ktds.subs.subscription.command.event;

import lombok.Getter;
import lombok.Builder;
import java.time.LocalDateTime;

@Getter
@Builder
public class SubscriptionEvent {
    private String eventType;
    private Long subscriptionId;
    private String userId;
    private String serviceName;
    private String category;
    private Long paymentAmount;
    private String paymentCycle;
    private Integer paymentDay;
    private LocalDateTime eventTime;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/build.gradle
dependencies {
    implementation project(':common')
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-data-mongodb'
    implementation 'org.springframework.kafka:spring-kafka'
    implementation 'org.springframework.boot:spring-boot-starter-cache'
    implementation 'org.springframework.boot:spring-boot-starter-data-redis'
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/resources/application.yml
spring:
  application:
    name: ${SPRING_APPLICATION_NAME:subscription-query-service}
  data:
    mongodb:
      uri: ${MONGODB_URI}
      database: ${MONGODB_DATABASE}
  redis:
    host: ${REDIS_HOST:localhost}
    port: ${REDIS_PORT:6379}
  kafka:
    bootstrap-servers: ${KAFKA_BOOTSTRAP_SERVERS}
    consumer:
      group-id: ${KAFKA_CONSUMER_GROUP_ID:subscription-query-service}
      auto-offset-reset: earliest
      key-deserializer: org.apache.kafka.common.serialization.StringDeserializer
      value-deserializer: org.springframework.kafka.support.serializer.JsonDeserializer

server:
  port: ${SERVER_PORT:8083}
  

// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/SubscriptionQueryServiceApplication.java
package com.ktds.subs.subscription.query;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@EnableCaching
public class SubscriptionQueryServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(SubscriptionQueryServiceApplication.class, args);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/dto/response/DashboardResponse.java
package com.ktds.subs.subscription.query.dto.response;

import lombok.Builder;
import lombok.Getter;
import java.util.List;

@Getter
@Builder
public class DashboardResponse {
    private Long totalAmount;
    private List<SubscriptionSummary> subscriptions;
    
    @Getter
    @Builder
    public static class SubscriptionSummary {
        private Long subscriptionId;
        private String serviceName;
        private String category;
        private Long paymentAmount;
        private String paymentCycle;
        private LocalDateTime nextPaymentDate;
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/dto/response/TotalAmountResponse.java
package com.ktds.subs.subscription.query.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class TotalAmountResponse {
    private Long totalAmount;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/dto/response/PaymentScheduleResponse.java
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


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/repository/SubscriptionViewRepository.java
package com.ktds.subs.subscription.query.repository;

import com.ktds.subs.subscription.query.domain.SubscriptionView;
import org.springframework.data.mongodb.repository.MongoRepository;
import java.util.List;

public interface SubscriptionViewRepository extends MongoRepository<SubscriptionView, Long> {
    List<SubscriptionView> findByUserId(String userId);
    List<SubscriptionView> findByUserIdAndCategory(String userId, String category);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/config/KafkaConfig.java
package com.ktds.subs.subscription.query.config;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.support.serializer.JsonDeserializer;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class KafkaConfig {

    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;

    @Value("${spring.kafka.consumer.group-id}")
    private String groupId;

    @Bean
    public ConsumerFactory<String, Object> consumerFactory() {
        Map<String, Object> configs = new HashMap<>();
        configs.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        configs.put(ConsumerConfig.GROUP_ID_CONFIG, groupId);
        configs.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        configs.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, JsonDeserializer.class);
        configs.put(JsonDeserializer.TRUSTED_PACKAGES, "com.ktds.subs.subscription.*");
        
        return new DefaultKafkaConsumerFactory<>(configs);
    }

    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, Object> kafkaListenerContainerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, Object> factory = 
            new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(consumerFactory());
        return factory;
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/config/RedisConfig.java
package com.ktds.subs.subscription.query.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {

    @Value("${spring.redis.host}")
    private String redisHost;

    @Value("${spring.redis.port}")
    private int redisPort;

    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        return new LettuceConnectionFactory(redisHost, redisPort);
    }

    @Bean
    public RedisTemplate<String, Object> redisTemplate() {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(redisConnectionFactory());
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
        return template;
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/controller/SubscriptionQueryController.java
package com.ktds.subs.subscription.query.controller;

import com.ktds.subs.common.dto.ApiResponse;
import com.ktds.subs.subscription.query.service.SubscriptionQueryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@Tag(name = "구독 조회", description = "구독 서비스 Query API")
@RestController
@RequestMapping("/api/subscriptions")
@RequiredArgsConstructor
public class SubscriptionQueryController {

    private final SubscriptionQueryService subscriptionQueryService;

    @Operation(summary = "구독 대시보드 조회", description = "사용자의 구독 서비스 요약 정보를 조회합니다.")
    @GetMapping("/summary")
    public ApiResponse<?> getDashboard(
            @RequestHeader("X-User-ID") String userId) {
        return ApiResponse.success(subscriptionQueryService.getDashboard(userId));
    }

    @Operation(summary = "카테고리별 구독 조회", description = "카테고리별 구독 서비스 목록을 조회합니다.")
    @GetMapping("/category")
    public ApiResponse<?> getSubscriptionsByCategory(
            @RequestHeader("X-User-ID") String userId,
            @RequestParam String category) {
        return ApiResponse.success(subscriptionQueryService.getSubscriptionsByCategory(userId, category));
    }

    @Operation(summary = "월별 결제일 조회", description = "특정 월의 결제 일정을 조회합니다.")
    @GetMapping("/calendar")
    public ApiResponse<?> getPaymentSchedule(
            @RequestHeader("X-User-ID") String userId,
            @RequestParam String yearMonth) {
        return ApiResponse.success(subscriptionQueryService.getPaymentSchedule(userId, yearMonth));
    }

    @Operation(summary = "월별 총액 조회", description = "특정 월의 총 결제 금액을 조회합니다.")
    @GetMapping("/total")
    public ApiResponse<?> getTotalAmount(
            @RequestHeader("X-User-ID") String userId,
            @RequestParam String yearMonth) {
        return ApiResponse.success(subscriptionQueryService.getTotalAmount(userId, yearMonth));
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/service/SubscriptionQueryService.java
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


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/service/impl/SubscriptionQueryServiceImpl.java
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


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/domain/SubscriptionView.java
package com.ktds.subs.subscription.query.domain;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import java.time.LocalDateTime;

@Document(collection = "subscription_views")
@Getter
@Setter
public class SubscriptionView {
    @Id
    private Long subscriptionId;
    
    private String userId;
    private String serviceName;
    private String category;
    private Long paymentAmount;
    private String paymentCycle;
    private Integer paymentDay;
    private LocalDateTime startDate;
    private LocalDateTime lastPaymentDate;
    private LocalDateTime nextPaymentDate;
    private Integer totalPayments;
    private Long totalAmount;
    private Double avgMonthlyAmount;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/event/SubscriptionEventListener.java
package com.ktds.subs.subscription.query.event;

import com.ktds.subs.subscription.query.domain.SubscriptionView;
import com.ktds.subs.subscription.query.repository.SubscriptionViewRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SubscriptionEventListener {

    private final SubscriptionViewRepository subscriptionViewRepository;

    @KafkaListener(topics = "subscription-events", groupId = "${spring.kafka.consumer.group-id}")
    public void handleSubscriptionEvent(SubscriptionEvent event) {
        switch (event.getEventType()) {
            case "SUBSCRIPTION_CREATED":
                handleSubscriptionCreated(event);
                break;
            case "SUBSCRIPTION_UPDATED":
                handleSubscriptionUpdated(event);
                break;
            case "SUBSCRIPTION_DELETED":
                handleSubscriptionDeleted(event);
                break;
        }
    }

    private void handleSubscriptionCreated(SubscriptionEvent event) {
        SubscriptionView view = new SubscriptionView();
        updateSubscriptionView(view, event);
        subscriptionViewRepository.save(view);
    }

    private void handleSubscriptionUpdated(SubscriptionEvent event) {
        subscriptionViewRepository.findById(event.getSubscriptionId())
            .ifPresent(view -> {
                updateSubscriptionView(view, event);
                subscriptionViewRepository.save(view);
            });
    }

    private void handleSubscriptionDeleted(SubscriptionEvent event) {
        subscriptionViewRepository.deleteById(event.getSubscriptionId());
    }

    private void updateSubscriptionView(SubscriptionView view, SubscriptionEvent event) {
        view.setSubscriptionId(event.getSubscriptionId());
        view.setUserId(event.getUserId());
        view.setServiceName(event.getServiceName());
        view.setCategory(event.getCategory());
        view.setPaymentAmount(event.getPaymentAmount());
        view.setPaymentCycle(event.getPaymentCycle());
        view.setPaymentDay(event.getPaymentDay());
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/build.gradle
dependencies {
    implementation project(':common')
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    implementation 'org.springframework.boot:spring-boot-starter-security'
    implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
    runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.5'
    runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.11.5'
    implementation 'mysql:mysql-connector-java:8.0.33'
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/resources/application.yml
spring:
  application:
    name: ${SPRING_APPLICATION_NAME:auth-service}
  datasource:
    url: ${DATASOURCE_URL}
    username: ${DATASOURCE_USERNAME}
    password: ${DATASOURCE_PASSWORD}
    driver-class-name: com.mysql.cj.jdbc.Driver
  jpa:
    hibernate:
      ddl-auto: validate
    properties:
      hibernate:
        format_sql: true
        show_sql: true

server:
  port: ${SERVER_PORT:8081}

jwt:
  secret: ${JWT_SECRET}
  access-token-validity: ${JWT_ACCESS_TOKEN_VALIDITY:3600000}

oauth2:
  google:
    client-id: ${GOOGLE_CLIENT_ID}
    client-secret: ${GOOGLE_CLIENT_SECRET}
    token-uri: https://oauth2.googleapis.com/token
    user-info-uri: https://www.googleapis.com/oauth2/v3/userinfo
    
    

// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/AuthServiceApplication.java
package com.ktds.subs.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/dto/GoogleUserInfo.java
package com.ktds.subs.auth.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class GoogleUserInfo {
    private String id;
    private String email;
    private String name;
    private String picture;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/dto/response/UserProfileResponse.java
package com.ktds.subs.auth.dto.response;

import com.ktds.subs.auth.domain.User;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class UserProfileResponse {
    private String userId;
    private String nickname;
    private String gender;

    public static UserProfileResponse from(User user) {
        return UserProfileResponse.builder()
            .userId(user.getUserId())
            .nickname(user.getNickname())
            .gender(user.getGender())
            .build();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/dto/response/NotificationSettingResponse.java
package com.ktds.subs.auth.dto.response;

import com.ktds.subs.auth.domain.User;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class NotificationSettingResponse {
    private boolean enabled;

    public static NotificationSettingResponse from(User user) {
        return NotificationSettingResponse.builder()
            .enabled(user.isNotificationEnabled())
            .build();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/dto/response/TokenResponse.java
package com.ktds.subs.auth.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class TokenResponse {
    private String accessToken;
    private String refreshToken;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/dto/request/SocialLoginRequest.java
package com.ktds.subs.auth.dto.request;

import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class SocialLoginRequest {
    private String provider;
    private String code;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/repository/TokenRepository.java
package com.ktds.subs.auth.repository;

import com.ktds.subs.auth.domain.Token;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByRefreshToken(String refreshToken);
    void deleteByUserId(String userId);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/repository/UserRepository.java
package com.ktds.subs.auth.repository;

import com.ktds.subs.auth.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findByProviderAndProviderUserId(String provider, String providerUserId);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/util/JwtTokenProvider.java
package com.ktds.subs.auth.util;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.UUID;

@Component
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.access-token-validity}")
    private long accessTokenValidityInMilliseconds;

    public String createAccessToken(String userId) {
        Claims claims = Jwts.claims().setSubject(userId);
        Date now = new Date();
        Date validity = new Date(now.getTime() + accessTokenValidityInMilliseconds);

        return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(validity)
            .signWith(SignatureAlgorithm.HS256, jwtSecret)
            .compact();
    }

    public String createRefreshToken() {
        return UUID.randomUUID().toString();
    }

    public String getUserId(String token) {
        return Jwts.parser()
            .setSigningKey(jwtSecret)
            .parseClaimsJws(token)
            .getBody()
            .getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/config/SecurityConfig.java
package com.ktds.subs.auth.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authorizeRequests()
            .requestMatchers("/api/auth/**").permitAll()
            .anyRequest().authenticated();
            
        return http.build();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/config/SwaggerConfig.java
package com.ktds.subs.auth.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {
    
    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("인증 서비스 API")
                .description("구독 관리 서비스의 인증 관련 API입니다.")
                .version("1.0"));
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/controller/AuthController.java
package com.ktds.subs.auth.controller;

import com.ktds.subs.auth.dto.request.SocialLoginRequest;
import com.ktds.subs.auth.dto.response.TokenResponse;
import com.ktds.subs.auth.service.AuthService;
import com.ktds.subs.common.dto.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@Tag(name = "인증", description = "인증 관련 API")
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    
    private final AuthService authService;
    
    @Operation(summary = "소셜 로그인", description = "소셜 계정으로 로그인합니다.")
    @PostMapping("/login")
    public ApiResponse<TokenResponse> login(@RequestBody SocialLoginRequest request) {
        return ApiResponse.success(authService.login(request.getProvider(), request.getCode()));
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/controller/UserController.java
package com.ktds.subs.auth.controller;

import com.ktds.subs.auth.service.UserService;
import com.ktds.subs.common.dto.ApiResponse;
import com.ktds.subs.auth.dto.request.UserProfileRequest;
import com.ktds.subs.auth.dto.request.NotificationSettingRequest;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@Tag(name = "사용자", description = "사용자 관련 API")
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @Operation(summary = "프로필 조회", description = "사용자 프로필을 조회합니다.")
    @GetMapping("/{userId}")
    public ApiResponse<?> getProfile(@PathVariable String userId) {
        return ApiResponse.success(userService.getProfile(userId));
    }

    @Operation(summary = "프로필 수정", description = "사용자 프로필을 수정합니다.")
    @PutMapping("/{userId}")
    public ApiResponse<?> updateProfile(
            @PathVariable String userId,
            @RequestBody UserProfileRequest request) {
        return ApiResponse.success(userService.updateProfile(userId, request));
    }

    @Operation(summary = "알림 설정 조회", description = "사용자의 알림 설정을 조회합니다.")
    @GetMapping("/{userId}/notifications")
    public ApiResponse<?> getNotificationSettings(@PathVariable String userId) {
        return ApiResponse.success(userService.getNotificationSettings(userId));
    }

    @Operation(summary = "알림 설정 수정", description = "사용자의 알림 설정을 수정합니다.")
    @PutMapping("/{userId}/notifications")
    public ApiResponse<?> updateNotificationSettings(
            @PathVariable String userId,
            @RequestBody NotificationSettingRequest request) {
        return ApiResponse.success(userService.updateNotificationSettings(userId, request));
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/service/UserService.java
package com.ktds.subs.auth.service;

import com.ktds.subs.auth.dto.request.UserProfileRequest;
import com.ktds.subs.auth.dto.request.NotificationSettingRequest;
import com.ktds.subs.auth.dto.response.UserProfileResponse;
import com.ktds.subs.auth.dto.response.NotificationSettingResponse;

public interface UserService {
    UserProfileResponse getProfile(String userId);
    UserProfileResponse updateProfile(String userId, UserProfileRequest request);
    NotificationSettingResponse getNotificationSettings(String userId);
    NotificationSettingResponse updateNotificationSettings(String userId, NotificationSettingRequest request);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/service/AuthService.java
package com.ktds.subs.auth.service;

import com.ktds.subs.auth.dto.response.TokenResponse;

public interface AuthService {
    TokenResponse login(String provider, String code);
    TokenResponse refresh(String refreshToken);
    void logout(String refreshToken);
    TokenResponse signup(String provider, String code);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/service/impl/UserServiceImpl.java
package com.ktds.subs.auth.service.impl;

import com.ktds.subs.auth.domain.User;
import com.ktds.subs.auth.dto.request.UserProfileRequest;
import com.ktds.subs.auth.dto.request.NotificationSettingRequest;
import com.ktds.subs.auth.dto.response.UserProfileResponse;
import com.ktds.subs.auth.dto.response.NotificationSettingResponse;
import com.ktds.subs.auth.repository.UserRepository;
import com.ktds.subs.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserProfileResponse getProfile(String userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        return UserProfileResponse.from(user);
    }

    @Override
    @Transactional
    public UserProfileResponse updateProfile(String userId, UserProfileRequest request) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        
        user.setNickname(request.getNickname());
        user.setGender(request.getGender());
        
        return UserProfileResponse.from(userRepository.save(user));
    }

    @Override
    @Transactional(readOnly = true)
    public NotificationSettingResponse getNotificationSettings(String userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        return NotificationSettingResponse.from(user);
    }

    @Override
    @Transactional
    public NotificationSettingResponse updateNotificationSettings(String userId, NotificationSettingRequest request) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        
        user.setNotificationEnabled(request.isEnabled());
        
        return NotificationSettingResponse.from(userRepository.save(user));
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/service/impl/AuthServiceImpl.java
package com.ktds.subs.auth.service.impl;

import com.ktds.subs.auth.domain.Token;
import com.ktds.subs.auth.domain.User;
import com.ktds.subs.auth.dto.response.TokenResponse;
import com.ktds.subs.auth.repository.TokenRepository;
import com.ktds.subs.auth.repository.UserRepository;
import com.ktds.subs.auth.service.AuthService;
import com.ktds.subs.auth.util.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final GoogleOAuthClient googleOAuthClient;

    @Override
    @Transactional
    public TokenResponse login(String provider, String code) {
        // 구글 OAuth로 사용자 정보 조회
        GoogleUserInfo userInfo = googleOAuthClient.getUserInfo(code);
        
        // 기존 사용자 조회 또는 새로운 사용자 생성
        User user = userRepository.findByProviderAndProviderUserId(provider, userInfo.getId())
            .orElseGet(() -> signup(provider, userInfo));

        // 토큰 생성
        String accessToken = jwtTokenProvider.createAccessToken(user.getUserId());
        String refreshToken = jwtTokenProvider.createRefreshToken();

        // Refresh 토큰 저장
        saveRefreshToken(user.getUserId(), refreshToken);

        return new TokenResponse(accessToken, refreshToken);
    }

    @Override
    @Transactional
    public TokenResponse refresh(String refreshToken) {
        // Refresh 토큰 검증
        Token token = tokenRepository.findByRefreshToken(refreshToken)
            .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        // 새로운 액세스 토큰 발급
        String newAccessToken = jwtTokenProvider.createAccessToken(token.getUserId());

        return new TokenResponse(newAccessToken, refreshToken);
    }

    @Override
    @Transactional
    public void logout(String refreshToken) {
        Token token = tokenRepository.findByRefreshToken(refreshToken)
            .orElseThrow(() -> new RuntimeException("Invalid refresh token"));
        tokenRepository.delete(token);
    }

    private User signup(String provider, GoogleUserInfo userInfo) {
        User user = new User();
        user.setUserId(UUID.randomUUID().toString());
        user.setProvider(provider);
        user.setProviderUserId(userInfo.getId());
        user.setNickname(userInfo.getName());
        return userRepository.save(user);
    }

    private void saveRefreshToken(String userId, String refreshToken) {
        Token token = new Token();
        token.setUserId(userId);
        token.setRefreshToken(refreshToken);
        token.setExpiresAt(LocalDateTime.now().plusDays(14));
        tokenRepository.save(token);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/domain/User.java
package com.ktds.subs.auth.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Getter
@NoArgsConstructor
public class User {
    @Id
    @Column(name = "user_id")
    private String userId;
    
    private String nickname;
    
    private String gender;
    
    private String provider;
    
    @Column(name = "provider_user_id")
    private String providerUserId;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
    
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/domain/Token.java
package com.ktds.subs.auth.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "refresh_tokens")
@Getter
@NoArgsConstructor
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "token_id")
    private Long tokenId;
    
    @Column(name = "user_id")
    private String userId;
    
    @Column(name = "refresh_token")
    private String refreshToken;
    
    @Column(name = "expires_at")
    private LocalDateTime expiresAt;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/client/GoogleOAuthClient.java


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/settings.gradle
rootProject.name = 'subs-mgmt'

include 'common'
include 'auth-service'
include 'subscription-command-service'
include 'subscription-query-service'
include 'notification-service'
include 'api-gateway'


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/notification-service/build.gradle
dependencies {
    implementation project(':common')
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    implementation 'org.springframework.kafka:spring-kafka'
    implementation 'com.google.firebase:firebase-admin:9.2.0'
    implementation 'mysql:mysql-connector-java:8.0.33'
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/notification-service/src/main/resources/application.yml
spring:
  application:
    name: ${SPRING_APPLICATION_NAME:notification-service}
  datasource:
    url: ${DATASOURCE_URL}
    username: ${DATASOURCE_USERNAME}
    password: ${DATASOURCE_PASSWORD}
    driver-class-name: com.mysql.cj.jdbc.Driver
  jpa:
    hibernate:
      ddl-auto: validate
    properties:
      hibernate:
        format_sql: true
        show_sql: true
  kafka:
    bootstrap-servers: ${KAFKA_BOOTSTRAP_SERVERS}
    consumer:
      group-id: ${KAFKA_CONSUMER_GROUP_ID:notification-service}
      auto-offset-reset: earliest

server:
  port: ${SERVER_PORT:8084}

firebase:
  config:
    path: ${FIREBASE_CONFIG_PATH:firebase-service-account.json}
    

// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/NotificationServiceApplication.java
package com.ktds.subs.notification;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class NotificationServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(NotificationServiceApplication.class, args);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/dto/response/TokenRegistrationResponse.java
package com.ktds.subs.notification.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import java.time.LocalDateTime;

@Getter
@AllArgsConstructor
public class TokenRegistrationResponse {
    private String status;
    private String message;
    private LocalDateTime registeredAt;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/dto/request/FCMTokenRequest.java
package com.ktds.subs.notification.dto.request;

import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class FCMTokenRequest {
    private String token;
    private String deviceInfo;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/repository/NotificationHistoryRepository.java
package com.ktds.subs.notification.repository;

import com.ktds.subs.notification.domain.NotificationHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface NotificationHistoryRepository extends JpaRepository<NotificationHistory, Long> {
    List<NotificationHistory> findByUserIdOrderBySentAtDesc(String userId);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/repository/FCMTokenRepository.java
package com.ktds.subs.notification.repository;

import com.ktds.subs.notification.domain.FCMToken;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface FCMTokenRepository extends JpaRepository<FCMToken, Long> {
    List<FCMToken> findByUserId(String userId);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/repository/NotificationSettingRepository.java
package com.ktds.subs.notification.repository;

import com.ktds.subs.notification.domain.NotificationSetting;
import org.springframework.data.jpa.repository.JpaRepository;

public interface NotificationSettingRepository extends JpaRepository<NotificationSetting, String> {
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/config/KafkaConfig.java
package com.ktds.subs.notification.config;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.support.serializer.JsonDeserializer;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class KafkaConfig {

    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;

    @Value("${spring.kafka.consumer.group-id}")
    private String groupId;

    @Bean
    public ConsumerFactory<String, Object> consumerFactory() {
        Map<String, Object> props = new HashMap<>();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ConsumerConfig.GROUP_ID_CONFIG, groupId);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, JsonDeserializer.class);
        props.put(JsonDeserializer.TRUSTED_PACKAGES, "*");
        
        return new DefaultKafkaConsumerFactory<>(props);
    }

    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, Object> kafkaListenerContainerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, Object> factory = 
            new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(consumerFactory());
        return factory;
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/config/FirebaseConfig.java
package com.ktds.subs.notification.config;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.messaging.FirebaseMessaging;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;

@Configuration
public class FirebaseConfig {

    @Value("${firebase.config.path}")
    private String firebaseConfigPath;

    @Bean
    public FirebaseMessaging firebaseMessaging() throws IOException {
        GoogleCredentials googleCredentials = GoogleCredentials
            .fromStream(new ClassPathResource(firebaseConfigPath).getInputStream());

        FirebaseOptions firebaseOptions = FirebaseOptions.builder()
            .setCredentials(googleCredentials)
            .build();

        FirebaseApp app = FirebaseApp.initializeApp(firebaseOptions);
        return FirebaseMessaging.getInstance(app);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/controller/NotificationController.java
package com.ktds.subs.notification.controller;

import com.ktds.subs.common.dto.ApiResponse;
import com.ktds.subs.notification.dto.request.FCMTokenRequest;
import com.ktds.subs.notification.service.NotificationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@Tag(name = "알림", description = "알림 관련 API")
@RestController
@RequestMapping("/api/notifications")
@RequiredArgsConstructor
public class NotificationController {

    private final NotificationService notificationService;

    @Operation(summary = "FCM 토큰 등록", description = "사용자의 FCM 토큰을 등록합니다.")
    @PostMapping("/token")
    public ApiResponse<?> registerToken(
            @RequestHeader("X-User-ID") String userId,
            @RequestBody FCMTokenRequest request) {
        return ApiResponse.success(notificationService.registerToken(userId, request));
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/service/FirebaseMessagingService.java
package com.ktds.subs.notification.service;

import com.google.firebase.messaging.FirebaseMessaging;
import com.google.firebase.messaging.Message;
import com.google.firebase.messaging.Notification;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class FirebaseMessagingService {

    private final FirebaseMessaging firebaseMessaging;

    public void sendMessage(String token, String title, String body) throws Exception {
        Message message = Message.builder()
            .setNotification(Notification.builder()
                .setTitle(title)
                .setBody(body)
                .build())
            .setToken(token)
            .build();

        firebaseMessaging.send(message);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/service/NotificationService.java
package com.ktds.subs.notification.service;

import com.ktds.subs.notification.dto.request.FCMTokenRequest;
import com.ktds.subs.notification.dto.response.TokenRegistrationResponse;
import com.ktds.subs.subscription.command.event.SubscriptionEvent;

public interface NotificationService {
    TokenRegistrationResponse registerToken(String userId, FCMTokenRequest request);
    void handleSubscriptionEvent(SubscriptionEvent event);
    void sendPaymentNotification(String userId, Long subscriptionId, String serviceName, Long paymentAmount);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/service/impl/NotificationServiceImpl.java
package com.ktds.subs.notification.service.impl;

import com.ktds.subs.notification.domain.FCMToken;
import com.ktds.subs.notification.domain.NotificationHistory;
import com.ktds.subs.notification.domain.NotificationSetting;
import com.ktds.subs.notification.dto.request.FCMTokenRequest;
import com.ktds.subs.notification.dto.response.TokenRegistrationResponse;
import com.ktds.subs.notification.repository.FCMTokenRepository;
import com.ktds.subs.notification.repository.NotificationHistoryRepository;
import com.ktds.subs.notification.repository.NotificationSettingRepository;
import com.ktds.subs.notification.service.NotificationService;
import com.ktds.subs.subscription.command.event.SubscriptionEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class NotificationServiceImpl implements NotificationService {

    private final FCMTokenRepository fcmTokenRepository;
    private final NotificationSettingRepository notificationSettingRepository;
    private final NotificationHistoryRepository notificationHistoryRepository;
    private final FirebaseMessagingService firebaseMessagingService;

    @Override
    @Transactional
    public TokenRegistrationResponse registerToken(String userId, FCMTokenRequest request) {
        FCMToken fcmToken = new FCMToken();
        fcmToken.setUserId(userId);
        fcmToken.setFcmToken(request.getToken());
        fcmToken.setDeviceInfo(request.getDeviceInfo());
        fcmTokenRepository.save(fcmToken);

        return new TokenRegistrationResponse(
            "SUCCESS",
            "FCM 토큰이 등록되었습니다.",
            LocalDateTime.now()
        );
    }

    @Override
    @Transactional
    public void handleSubscriptionEvent(SubscriptionEvent event) {
        switch (event.getEventType()) {
            case "SUBSCRIPTION_CREATED":
                sendWelcomeNotification(event);
                break;
            case "SUBSCRIPTION_UPDATED":
                sendUpdateNotification(event);
                break;
            case "SUBSCRIPTION_DELETED":
                sendDeleteNotification(event);
                break;
        }
    }

    @Override
    @Transactional
    public void sendPaymentNotification(String userId, Long subscriptionId, String serviceName, Long paymentAmount) {
        NotificationSetting setting = notificationSettingRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("알림 설정을 찾을 수 없습니다."));

        if (!setting.isPaymentNotification()) {
            return;
        }

        List<FCMToken> tokens = fcmTokenRepository.findByUserId(userId);
        String title = "결제 예정 알림";
        String message = String.format("%s 서비스의 결제(%,d원)가 예정되어 있습니다.", serviceName, paymentAmount);

        tokens.forEach(token -> {
            try {
                firebaseMessagingService.sendMessage(token.getFcmToken(), title, message);
                saveNotificationHistory(userId, subscriptionId, "PAYMENT", title, message);
            } catch (Exception e) {
                // 토큰이 만료되었거나 유효하지 않은 경우 처리
                fcmTokenRepository.delete(token);
            }
        });
    }

    private void sendWelcomeNotification(SubscriptionEvent event) {
        String title = "구독 서비스 등록";
        String message = String.format("%s 서비스가 등록되었습니다.", event.getServiceName());
        sendNotification(event.getUserId(), event.getSubscriptionId(), "WELCOME", title, message);
    }

    private void sendUpdateNotification(SubscriptionEvent event) {
        String title = "구독 서비스 수정";
        String message = String.format("%s 서비스 정보가 수정되었습니다.", event.getServiceName());
        sendNotification(event.getUserId(), event.getSubscriptionId(), "UPDATE", title, message);
    }

    private void sendDeleteNotification(SubscriptionEvent event) {
        String title = "구독 서비스 삭제";
        String message = String.format("%s 서비스가 삭제되었습니다.", event.getServiceName());
        sendNotification(event.getUserId(), event.getSubscriptionId(), "DELETE", title, message);
    }

    private void sendNotification(String userId, Long subscriptionId, String type, String title, String message) {
        List<FCMToken> tokens = fcmTokenRepository.findByUserId(userId);
        tokens.forEach(token -> {
            try {
                firebaseMessagingService.sendMessage(token.getFcmToken(), title, message);
                saveNotificationHistory(userId, subscriptionId, type, title, message);
            } catch (Exception e) {
                fcmTokenRepository.delete(token);
            }
        });
    }

    private void saveNotificationHistory(String userId, Long subscriptionId, String type, String title, String message) {
        NotificationHistory history = new NotificationHistory();
        history.setUserId(userId);
        history.setSubscriptionId(subscriptionId);
        history.setNotificationType(type);
        history.setTitle(title);
        history.setMessage(message);
        history.setSentAt(LocalDateTime.now());
        notificationHistoryRepository.save(history);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/domain/NotificationHistory.java
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


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/domain/NotificationSetting.java
package com.ktds.subs.notification.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;
import java.time.LocalTime;

@Entity
@Table(name = "notification_settings")
@Getter
@NoArgsConstructor
public class NotificationSetting {
    @Id
    @Column(name = "user_id")
    private String userId;
    
    @Column(name = "payment_notification")
    private boolean paymentNotification;
    
    @Column(name = "notification_time")
    private LocalTime notificationTime;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
    
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/domain/FCMToken.java
package com.ktds.subs.notification.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "fcm_tokens")
@Getter
@NoArgsConstructor
public class FCMToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "token_id")
    private Long tokenId;
    
    @Column(name = "user_id")
    private String userId;
    
    @Column(name = "fcm_token")
    private String fcmToken;
    
    @Column(name = "device_info")
    private String deviceInfo;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/notification-service/src/main/java/com/ktds/subs/notification/event/SubscriptionEventListener.java
package com.ktds.subs.notification.event;

import com.ktds.subs.notification.service.NotificationService;
import com.ktds.subs.subscription.command.event.SubscriptionEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SubscriptionEventListener {

    private final NotificationService notificationService;

    @KafkaListener(topics = "subscription-events", groupId = "${spring.kafka.consumer.group-id}")
    public void handleSubscriptionEvent(SubscriptionEvent event) {
        notificationService.handleSubscriptionEvent(event);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/api-gateway/build.gradle
dependencies {
    implementation 'org.springframework.cloud:spring-cloud-starter-gateway'
    implementation 'org.springframework.cloud:spring-cloud-starter-netflix-eureka-client'
    implementation 'org.springframework.boot:spring-boot-starter-security'
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/api-gateway/src/main/resources/application.yml
spring:
  application:
    name: ${SPRING_APPLICATION_NAME:api-gateway}
  cloud:
    gateway:
      routes:
        - id: auth-service
          uri: lb://auth-service
          predicates:
            - Path=/api/auth/**
          filters:
            - RewritePath=/api/auth/(?<segment>.*), /api/auth/${segment}

        - id: subscription-command-service
          uri: lb://subscription-command-service
          predicates:
            - Path=/api/subscriptions/**
            - Method=POST,PUT,DELETE
          filters:
            - RewritePath=/api/subscriptions/(?<segment>.*), /api/subscriptions/${segment}

        - id: subscription-query-service
          uri: lb://subscription-query-service
          predicates:
            - Path=/api/subscriptions/**
            - Method=GET
          filters:
            - RewritePath=/api/subscriptions/(?<segment>.*), /api/subscriptions/${segment}

        - id: notification-service
          uri: lb://notification-service
          predicates:
            - Path=/api/notifications/**
          filters:
            - RewritePath=/api/notifications/(?<segment>.*), /api/notifications/${segment}

  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: ${JWT_JWK_SET_URI}

server:
  port: ${SERVER_PORT:8080}

eureka:
  client:
    service-url:
      defaultZone: ${EUREKA_SERVICE_URL:http://localhost:8761/eureka/}
    fetch-registry: true
    register-with-eureka: true
  instance:
    prefer-ip-address: true

jwt:
  secret: ${JWT_SECRET}

management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics
        


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/api-gateway/src/main/java/com/ktds/subs/gateway/ApiGatewayApplication.java
package com.ktds.subs.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class ApiGatewayApplication {
    public static void main(String[] args) {
        SpringApplication.run(ApiGatewayApplication.class, args);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/api-gateway/src/main/java/com/ktds/subs/gateway/util/JwtTokenProvider.java
package com.ktds.subs.gateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Component
public class JwtTokenProvider {

    private final SecretKey key;

    public JwtTokenProvider(@Value("${jwt.secret}") String secret) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public String getUserId(String token) {
        Claims claims = Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)
            .getBody();
        return claims.getSubject();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/api-gateway/src/main/java/com/ktds/subs/gateway/config/SecurityConfig.java
package com.ktds.subs.gateway.config;

import com.ktds.subs.gateway.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
            .csrf().disable()
            .formLogin().disable()
            .httpBasic().disable()
            .authorizeExchange()
            .pathMatchers("/api/auth/**").permitAll()
            .pathMatchers("/actuator/**").permitAll()
            .anyExchange().authenticated()
            .and()
            .addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
            .build();
    }

    @Bean
    public CorsWebFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList("*"));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(Arrays.asList("*"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return new CorsWebFilter(source);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/api-gateway/src/main/java/com/ktds/subs/gateway/filter/JwtAuthenticationFilter.java
package com.ktds.subs.gateway.filter;

import com.ktds.subs.gateway.util.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        
        // Skip authentication for public endpoints
        if (path.startsWith("/api/auth/") || path.startsWith("/actuator/")) {
            return chain.filter(exchange);
        }

        String token = extractToken(exchange);
        
        if (token == null || !jwtTokenProvider.validateToken(token)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // Add user ID to request header
        String userId = jwtTokenProvider.getUserId(token);
        ServerWebExchange modifiedExchange = exchange.mutate()
            .request(exchange.getRequest().mutate()
                .header("X-User-ID", userId)
                .build())
            .build();

        return chain.filter(modifiedExchange);
    }

    private String extractToken(ServerWebExchange exchange) {
        String bearerToken = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/common/build.gradle
dependencies {
    implementation 'com.fasterxml.jackson.core:jackson-databind'
    implementation 'org.springframework.boot:spring-boot-starter-web'
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/common/src/main/resources/application.yml
server:
  port: ${SERVER_PORT:0}

spring:
  application:
    name: ${SPRING_APPLICATION_NAME}
  
  jpa:
    hibernate:
      ddl-auto: validate
    properties:
      hibernate:
        format_sql: true
        show_sql: true
        
logging:
  level:
    root: INFO
    com.ktds: DEBUG


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/common/src/main/java/com/ktds/subs/common/dto/ApiResponse.java
package com.ktds.subs.common.dto;

import lombok.Getter;
import java.time.LocalDateTime;

@Getter
public class ApiResponse<T> {
    private final String status;
    private final String message;
    private final T data;
    private final LocalDateTime timestamp;

    private ApiResponse(String status, String message, T data) {
        this.status = status;
        this.message = message;
        this.data = data;
        this.timestamp = LocalDateTime.now();
    }

    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>("SUCCESS", null, data);
    }

    public static <T> ApiResponse<T> error(String message) {
        return new ApiResponse<>("ERROR", message, null);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/common/src/main/java/com/ktds/subs/common/constant/ErrorCode.java
package com.ktds.subs.common.constant;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {
    // Common Errors
    INVALID_INPUT_VALUE("C001", "Invalid Input Value"),
    METHOD_NOT_ALLOWED("C002", "Method Not Allowed"),
    ENTITY_NOT_FOUND("C003", "Entity Not Found"),
    INTERNAL_SERVER_ERROR("C004", "Internal Server Error"),
    INVALID_TYPE_VALUE("C005", "Invalid Type Value"),
    ACCESS_DENIED("C006", "Access Denied"),
    
    // Auth Errors
    INVALID_AUTH_TOKEN("A001", "Invalid Auth Token"),
    EXPIRED_AUTH_TOKEN("A002", "Expired Auth Token"),
    UNAUTHORIZED("A003", "Unauthorized"),
    INVALID_SOCIAL_TOKEN("A004", "Invalid Social Token"),
    
    // Subscription Errors
    DUPLICATE_SUBSCRIPTION("S001", "Duplicate Subscription"),
    INVALID_SUBSCRIPTION("S002", "Invalid Subscription"),
    SUBSCRIPTION_NOT_FOUND("S003", "Subscription Not Found"),
    
    // Notification Errors
    NOTIFICATION_SEND_FAILED("N001", "Notification Send Failed"),
    INVALID_FCM_TOKEN("N002", "Invalid FCM Token");

    private final String code;
    private final String message;
}









    
    
    

// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/common/src/main/java/com/ktds/subs/common/exception/BaseException.java
package com.ktds.subs.common.exception;

import lombok.Getter;

@Getter
public class BaseException extends RuntimeException {
    private final String errorCode;
    
    public BaseException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-command-service/build.gradle
dependencies {
    implementation project(':common')
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    implementation 'org.springframework.kafka:spring-kafka'
    implementation 'mysql:mysql-connector-java:8.0.33'
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-command-service/src/main/resources/application.yml
spring:
  application:
    name: ${SPRING_APPLICATION_NAME:subscription-command-service}
  datasource:
    url: ${DATASOURCE_URL}
    username: ${DATASOURCE_USERNAME}
    password: ${DATASOURCE_PASSWORD}
    driver-class-name: com.mysql.cj.jdbc.Driver
  jpa:
    hibernate:
      ddl-auto: validate
    properties:
      hibernate:
        format_sql: true
        show_sql: true
  kafka:
    bootstrap-servers: ${KAFKA_BOOTSTRAP_SERVERS}
    producer:
      key-serializer: org.apache.kafka.common.serialization.StringSerializer
      value-serializer: org.springframework.kafka.support.serializer.JsonSerializer

server:
  port: ${SERVER_PORT:8082}
  

// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/SubscriptionCommandServiceApplication.java
package com.ktds.subs.subscription.command;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SubscriptionCommandServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(SubscriptionCommandServiceApplication.class, args);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/dto/response/SubscriptionResponse.java
package com.ktds.subs.subscription.command.dto.response;

import com.ktds.subs.subscription.command.domain.Subscription;
import lombok.Getter;
import lombok.Builder;

import java.time.LocalDateTime;

@Getter
@Builder
public class SubscriptionResponse {
    private Long subscriptionId;
    private String serviceName;
    private String category;
    private Long paymentAmount;
    private String paymentCycle;
    private Integer paymentDay;
    private LocalDateTime startDate;
    private LocalDateTime lastPaymentDate;
    private LocalDateTime nextPaymentDate;
    
    public static SubscriptionResponse from(Subscription subscription) {
        return SubscriptionResponse.builder()
            .subscriptionId(subscription.getSubscriptionId())
            .serviceName(subscription.getServiceName())
            .category(subscription.getCategory())
            .paymentAmount(subscription.getPaymentAmount())
            .paymentCycle(subscription.getPaymentCycle())
            .paymentDay(subscription.getPaymentDay())
            .startDate(subscription.getStartDate())
            .lastPaymentDate(subscription.getLastPaymentDate())
            .nextPaymentDate(subscription.getNextPaymentDate())
            .build();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/dto/response/DeleteResponse.java
package com.ktds.subs.subscription.command.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import java.time.LocalDateTime;

@Getter
@AllArgsConstructor
public class DeleteResponse {
    private String status;
    private String message;
    private LocalDateTime deletedAt;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/dto/request/SubscriptionCreateRequest.java
package com.ktds.subs.subscription.command.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.Getter;

@Getter
public class SubscriptionCreateRequest {
    @NotBlank(message = "서비스명은 필수입니다.")
    private String serviceName;
    
    @NotBlank(message = "카테고리는 필수입니다.")
    private String category;
    
    @NotNull(message = "결제금액은 필수입니다.")
    @Positive(message = "결제금액은 양수여야 합니다.")
    private Long paymentAmount;
    
    @NotBlank(message = "결제주기는 필수입니다.")
    private String paymentCycle;
    
    @NotNull(message = "결제일은 필수입니다.")
    private Integer paymentDay;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/dto/request/SubscriptionUpdateRequest.java
package com.ktds.subs.subscription.command.dto.request;

import jakarta.validation.constraints.Positive;
import lombok.Getter;

@Getter
public class SubscriptionUpdateRequest {
    @Positive(message = "결제금액은 양수여야 합니다.")
    private Long paymentAmount;
    
    private String paymentCycle;
    private Integer paymentDay;
    private String category;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/repository/SubscriptionCommandRepository.java
package com.ktds.subs.subscription.command.repository;

import com.ktds.subs.subscription.command.domain.Subscription;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SubscriptionCommandRepository extends JpaRepository<Subscription, Long> {
    boolean existsByUserIdAndServiceNameAndDeletedAtIsNull(String userId, String serviceName);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/config/KafkaConfig.java
package com.ktds.subs.subscription.command.config;

import com.ktds.subs.subscription.command.event.SubscriptionEvent;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;
import org.springframework.kafka.support.serializer.JsonSerializer;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class KafkaConfig {

    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;

    @Bean
    public ProducerFactory<String, SubscriptionEvent> producerFactory() {
        Map<String, Object> configs = new HashMap<>();
        configs.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        configs.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        configs.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);
        return new DefaultKafkaProducerFactory<>(configs);
    }

    @Bean
    public KafkaTemplate<String, SubscriptionEvent> kafkaTemplate() {
        return new KafkaTemplate<>(producerFactory());
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/controller/SubscriptionCommandController.java
package com.ktds.subs.subscription.command.controller;

import com.ktds.subs.common.dto.ApiResponse;
import com.ktds.subs.subscription.command.dto.request.SubscriptionCreateRequest;
import com.ktds.subs.subscription.command.dto.request.SubscriptionUpdateRequest;
import com.ktds.subs.subscription.command.service.SubscriptionCommandService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@Tag(name = "구독 관리", description = "구독 서비스 Command API")
@RestController
@RequestMapping("/api/subscriptions")
@RequiredArgsConstructor
public class SubscriptionCommandController {

    private final SubscriptionCommandService subscriptionCommandService;

    @Operation(summary = "구독 서비스 등록", description = "새로운 구독 서비스를 등록합니다.")
    @PostMapping
    public ApiResponse<?> createSubscription(
            @RequestHeader("X-User-ID") String userId,
            @RequestBody SubscriptionCreateRequest request) {
        return ApiResponse.success(subscriptionCommandService.createSubscription(userId, request));
    }

    @Operation(summary = "구독 서비스 수정", description = "기존 구독 서비스 정보를 수정합니다.")
    @PutMapping("/{subscriptionId}")
    public ApiResponse<?> updateSubscription(
            @RequestHeader("X-User-ID") String userId,
            @PathVariable Long subscriptionId,
            @RequestBody SubscriptionUpdateRequest request) {
        return ApiResponse.success(subscriptionCommandService.updateSubscription(userId, subscriptionId, request));
    }

    @Operation(summary = "구독 서비스 삭제", description = "구독 서비스를 삭제합니다.")
    @DeleteMapping("/{subscriptionId}")
    public ApiResponse<?> deleteSubscription(
            @RequestHeader("X-User-ID") String userId,
            @PathVariable Long subscriptionId) {
        return ApiResponse.success(subscriptionCommandService.deleteSubscription(userId, subscriptionId));
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/service/SubscriptionCommandService.java
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


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/service/impl/SubscriptionCommandServiceImpl.java
package com.ktds.subs.subscription.command.service.impl;

import com.ktds.subs.subscription.command.domain.Subscription;
import com.ktds.subs.subscription.command.dto.request.SubscriptionCreateRequest;
import com.ktds.subs.subscription.command.dto.request.SubscriptionUpdateRequest;
import com.ktds.subs.subscription.command.dto.response.DeleteResponse;
import com.ktds.subs.subscription.command.dto.response.SubscriptionResponse;
import com.ktds.subs.subscription.command.event.SubscriptionEvent;
import com.ktds.subs.subscription.command.repository.SubscriptionCommandRepository;
import com.ktds.subs.subscription.command.service.SubscriptionCommandService;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class SubscriptionCommandServiceImpl implements SubscriptionCommandService {

    private final SubscriptionCommandRepository subscriptionRepository;
    private final KafkaTemplate<String, SubscriptionEvent> kafkaTemplate;
    private static final String TOPIC = "subscription-events";

    @Override
    @Transactional
    public SubscriptionResponse createSubscription(String userId, SubscriptionCreateRequest request) {
        // 중복 구독 체크
        if (subscriptionRepository.existsByUserIdAndServiceNameAndDeletedAtIsNull(userId, request.getServiceName())) {
            throw new RuntimeException("이미 구독 중인 서비스입니다.");
        }

        // 구독 생성
        Subscription subscription = new Subscription();
        subscription.setUserId(userId);
        subscription.setServiceName(request.getServiceName());
        subscription.setCategory(request.getCategory());
        subscription.setPaymentAmount(request.getPaymentAmount());
        subscription.setPaymentCycle(request.getPaymentCycle());
        subscription.setPaymentDay(request.getPaymentDay());

        Subscription savedSubscription = subscriptionRepository.save(subscription);

        // 이벤트 발행
        publishSubscriptionEvent("SUBSCRIPTION_CREATED", savedSubscription);

        return SubscriptionResponse.from(savedSubscription);
    }

    @Override
    @Transactional
    public SubscriptionResponse updateSubscription(String userId, Long subscriptionId, SubscriptionUpdateRequest request) {
        Subscription subscription = subscriptionRepository.findById(subscriptionId)
            .orElseThrow(() -> new RuntimeException("구독 정보를 찾을 수 없습니다."));

        if (!subscription.getUserId().equals(userId)) {
            throw new RuntimeException("수정 권한이 없습니다.");
        }

        // 구독 정보 업데이트
        subscription.update(request);
        Subscription updatedSubscription = subscriptionRepository.save(subscription);

        // 이벤트 발행
        publishSubscriptionEvent("SUBSCRIPTION_UPDATED", updatedSubscription);

        return SubscriptionResponse.from(updatedSubscription);
    }

    @Override
    @Transactional
    public DeleteResponse deleteSubscription(String userId, Long subscriptionId) {
        Subscription subscription = subscriptionRepository.findById(subscriptionId)
            .orElseThrow(() -> new RuntimeException("구독 정보를 찾을 수 없습니다."));

        if (!subscription.getUserId().equals(userId)) {
            throw new RuntimeException("삭제 권한이 없습니다.");
        }

        subscription.setDeletedAt(LocalDateTime.now());
        subscriptionRepository.save(subscription);

        // 이벤트 발행
        publishSubscriptionEvent("SUBSCRIPTION_DELETED", subscription);

        return new DeleteResponse("SUCCESS", "구독이 삭제되었습니다.", LocalDateTime.now());
    }

    private void publishSubscriptionEvent(String eventType, Subscription subscription) {
        SubscriptionEvent event = SubscriptionEvent.builder()
            .eventType(eventType)
            .subscriptionId(subscription.getSubscriptionId())
            .userId(subscription.getUserId())
            .serviceName(subscription.getServiceName())
            .category(subscription.getCategory())
            .paymentAmount(subscription.getPaymentAmount())
            .paymentCycle(subscription.getPaymentCycle())
            .paymentDay(subscription.getPaymentDay())
            .eventTime(LocalDateTime.now())
            .build();

        kafkaTemplate.send(TOPIC, event);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/domain/Subscription.java
package com.ktds.subs.subscription.command.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "subscriptions")
@Getter
@NoArgsConstructor
public class Subscription {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "subscription_id")
    private Long subscriptionId;
    
    @Column(name = "user_id")
    private String userId;
    
    @Column(name = "service_name")
    private String serviceName;
    
    private String category;
    
    @Column(name = "payment_amount")
    private Long paymentAmount;
    
    @Column(name = "payment_cycle")
    private String paymentCycle;
    
    @Column(name = "payment_day")
    private Integer paymentDay;
    
    @Column(name = "start_date")
    private LocalDateTime startDate;
    
    @Column(name = "last_payment_date")
    private LocalDateTime lastPaymentDate;
    
    @Column(name = "next_payment_date")
    private LocalDateTime nextPaymentDate;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        startDate = LocalDateTime.now();
        calculateNextPaymentDate();
    }
    
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
        calculateNextPaymentDate();
    }
    
    private void calculateNextPaymentDate() {
        // 다음 결제일 계산 로직
        if (lastPaymentDate == null) {
            lastPaymentDate = startDate;
        }
        
        // payment_cycle에 따른 다음 결제일 계산
        switch (paymentCycle.toUpperCase()) {
            case "MONTHLY":
                nextPaymentDate = lastPaymentDate.plusMonths(1);
                break;
            case "YEARLY":
                nextPaymentDate = lastPaymentDate.plusYears(1);
                break;
            default:
                nextPaymentDate = lastPaymentDate.plusMonths(1);
        }
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-command-service/src/main/java/com/ktds/subs/subscription/command/event/SubscriptionEvent.java
package com.ktds.subs.subscription.command.event;

import lombok.Getter;
import lombok.Builder;
import java.time.LocalDateTime;

@Getter
@Builder
public class SubscriptionEvent {
    private String eventType;
    private Long subscriptionId;
    private String userId;
    private String serviceName;
    private String category;
    private Long paymentAmount;
    private String paymentCycle;
    private Integer paymentDay;
    private LocalDateTime eventTime;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-query-service/build.gradle
dependencies {
    implementation project(':common')
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-data-mongodb'
    implementation 'org.springframework.kafka:spring-kafka'
    implementation 'org.springframework.boot:spring-boot-starter-cache'
    implementation 'org.springframework.boot:spring-boot-starter-data-redis'
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-query-service/src/main/resources/application.yml
spring:
  application:
    name: ${SPRING_APPLICATION_NAME:subscription-query-service}
  data:
    mongodb:
      uri: ${MONGODB_URI}
      database: ${MONGODB_DATABASE}
  redis:
    host: ${REDIS_HOST:localhost}
    port: ${REDIS_PORT:6379}
  kafka:
    bootstrap-servers: ${KAFKA_BOOTSTRAP_SERVERS}
    consumer:
      group-id: ${KAFKA_CONSUMER_GROUP_ID:subscription-query-service}
      auto-offset-reset: earliest
      key-deserializer: org.apache.kafka.common.serialization.StringDeserializer
      value-deserializer: org.springframework.kafka.support.serializer.JsonDeserializer

server:
  port: ${SERVER_PORT:8083}
  

// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/SubscriptionQueryServiceApplication.java
package com.ktds.subs.subscription.query;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@EnableCaching
public class SubscriptionQueryServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(SubscriptionQueryServiceApplication.class, args);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/dto/response/DashboardResponse.java
package com.ktds.subs.subscription.query.dto.response;

import lombok.Builder;
import lombok.Getter;
import java.util.List;

@Getter
@Builder
public class DashboardResponse {
    private Long totalAmount;
    private List<SubscriptionSummary> subscriptions;
    
    @Getter
    @Builder
    public static class SubscriptionSummary {
        private Long subscriptionId;
        private String serviceName;
        private String category;
        private Long paymentAmount;
        private String paymentCycle;
        private LocalDateTime nextPaymentDate;
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/dto/response/TotalAmountResponse.java
package com.ktds.subs.subscription.query.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class TotalAmountResponse {
    private Long totalAmount;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/dto/response/PaymentScheduleResponse.java
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


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/repository/SubscriptionViewRepository.java
package com.ktds.subs.subscription.query.repository;

import com.ktds.subs.subscription.query.domain.SubscriptionView;
import org.springframework.data.mongodb.repository.MongoRepository;
import java.util.List;

public interface SubscriptionViewRepository extends MongoRepository<SubscriptionView, Long> {
    List<SubscriptionView> findByUserId(String userId);
    List<SubscriptionView> findByUserIdAndCategory(String userId, String category);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/config/KafkaConfig.java
package com.ktds.subs.subscription.query.config;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.support.serializer.JsonDeserializer;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class KafkaConfig {

    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;

    @Value("${spring.kafka.consumer.group-id}")
    private String groupId;

    @Bean
    public ConsumerFactory<String, Object> consumerFactory() {
        Map<String, Object> configs = new HashMap<>();
        configs.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        configs.put(ConsumerConfig.GROUP_ID_CONFIG, groupId);
        configs.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        configs.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, JsonDeserializer.class);
        configs.put(JsonDeserializer.TRUSTED_PACKAGES, "com.ktds.subs.subscription.*");
        
        return new DefaultKafkaConsumerFactory<>(configs);
    }

    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, Object> kafkaListenerContainerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, Object> factory = 
            new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(consumerFactory());
        return factory;
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/config/RedisConfig.java
package com.ktds.subs.subscription.query.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {

    @Value("${spring.redis.host}")
    private String redisHost;

    @Value("${spring.redis.port}")
    private int redisPort;

    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        return new LettuceConnectionFactory(redisHost, redisPort);
    }

    @Bean
    public RedisTemplate<String, Object> redisTemplate() {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(redisConnectionFactory());
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
        return template;
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/controller/SubscriptionQueryController.java
package com.ktds.subs.subscription.query.controller;

import com.ktds.subs.common.dto.ApiResponse;
import com.ktds.subs.subscription.query.service.SubscriptionQueryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@Tag(name = "구독 조회", description = "구독 서비스 Query API")
@RestController
@RequestMapping("/api/subscriptions")
@RequiredArgsConstructor
public class SubscriptionQueryController {

    private final SubscriptionQueryService subscriptionQueryService;

    @Operation(summary = "구독 대시보드 조회", description = "사용자의 구독 서비스 요약 정보를 조회합니다.")
    @GetMapping("/summary")
    public ApiResponse<?> getDashboard(
            @RequestHeader("X-User-ID") String userId) {
        return ApiResponse.success(subscriptionQueryService.getDashboard(userId));
    }

    @Operation(summary = "카테고리별 구독 조회", description = "카테고리별 구독 서비스 목록을 조회합니다.")
    @GetMapping("/category")
    public ApiResponse<?> getSubscriptionsByCategory(
            @RequestHeader("X-User-ID") String userId,
            @RequestParam String category) {
        return ApiResponse.success(subscriptionQueryService.getSubscriptionsByCategory(userId, category));
    }

    @Operation(summary = "월별 결제일 조회", description = "특정 월의 결제 일정을 조회합니다.")
    @GetMapping("/calendar")
    public ApiResponse<?> getPaymentSchedule(
            @RequestHeader("X-User-ID") String userId,
            @RequestParam String yearMonth) {
        return ApiResponse.success(subscriptionQueryService.getPaymentSchedule(userId, yearMonth));
    }

    @Operation(summary = "월별 총액 조회", description = "특정 월의 총 결제 금액을 조회합니다.")
    @GetMapping("/total")
    public ApiResponse<?> getTotalAmount(
            @RequestHeader("X-User-ID") String userId,
            @RequestParam String yearMonth) {
        return ApiResponse.success(subscriptionQueryService.getTotalAmount(userId, yearMonth));
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/service/SubscriptionQueryService.java
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


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/service/impl/SubscriptionQueryServiceImpl.java
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


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/domain/SubscriptionView.java
package com.ktds.subs.subscription.query.domain;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import java.time.LocalDateTime;

@Document(collection = "subscription_views")
@Getter
@Setter
public class SubscriptionView {
    @Id
    private Long subscriptionId;
    
    private String userId;
    private String serviceName;
    private String category;
    private Long paymentAmount;
    private String paymentCycle;
    private Integer paymentDay;
    private LocalDateTime startDate;
    private LocalDateTime lastPaymentDate;
    private LocalDateTime nextPaymentDate;
    private Integer totalPayments;
    private Long totalAmount;
    private Double avgMonthlyAmount;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/subscription-query-service/src/main/java/com/ktds/subs/subscription/query/event/SubscriptionEventListener.java
package com.ktds.subs.subscription.query.event;

import com.ktds.subs.subscription.query.domain.SubscriptionView;
import com.ktds.subs.subscription.query.repository.SubscriptionViewRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SubscriptionEventListener {

    private final SubscriptionViewRepository subscriptionViewRepository;

    @KafkaListener(topics = "subscription-events", groupId = "${spring.kafka.consumer.group-id}")
    public void handleSubscriptionEvent(SubscriptionEvent event) {
        switch (event.getEventType()) {
            case "SUBSCRIPTION_CREATED":
                handleSubscriptionCreated(event);
                break;
            case "SUBSCRIPTION_UPDATED":
                handleSubscriptionUpdated(event);
                break;
            case "SUBSCRIPTION_DELETED":
                handleSubscriptionDeleted(event);
                break;
        }
    }

    private void handleSubscriptionCreated(SubscriptionEvent event) {
        SubscriptionView view = new SubscriptionView();
        updateSubscriptionView(view, event);
        subscriptionViewRepository.save(view);
    }

    private void handleSubscriptionUpdated(SubscriptionEvent event) {
        subscriptionViewRepository.findById(event.getSubscriptionId())
            .ifPresent(view -> {
                updateSubscriptionView(view, event);
                subscriptionViewRepository.save(view);
            });
    }

    private void handleSubscriptionDeleted(SubscriptionEvent event) {
        subscriptionViewRepository.deleteById(event.getSubscriptionId());
    }

    private void updateSubscriptionView(SubscriptionView view, SubscriptionEvent event) {
        view.setSubscriptionId(event.getSubscriptionId());
        view.setUserId(event.getUserId());
        view.setServiceName(event.getServiceName());
        view.setCategory(event.getCategory());
        view.setPaymentAmount(event.getPaymentAmount());
        view.setPaymentCycle(event.getPaymentCycle());
        view.setPaymentDay(event.getPaymentDay());
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/auth-service/build.gradle
dependencies {
    implementation project(':common')
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    implementation 'org.springframework.boot:spring-boot-starter-security'
    implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
    runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.5'
    runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.11.5'
    implementation 'mysql:mysql-connector-java:8.0.33'
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/auth-service/src/main/resources/application.yml
spring:
  application:
    name: ${SPRING_APPLICATION_NAME:auth-service}
  datasource:
    url: ${DATASOURCE_URL}
    username: ${DATASOURCE_USERNAME}
    password: ${DATASOURCE_PASSWORD}
    driver-class-name: com.mysql.cj.jdbc.Driver
  jpa:
    hibernate:
      ddl-auto: validate
    properties:
      hibernate:
        format_sql: true
        show_sql: true

server:
  port: ${SERVER_PORT:8081}

jwt:
  secret: ${JWT_SECRET}
  access-token-validity: ${JWT_ACCESS_TOKEN_VALIDITY:3600000}

oauth2:
  google:
    client-id: ${GOOGLE_CLIENT_ID}
    client-secret: ${GOOGLE_CLIENT_SECRET}
    token-uri: https://oauth2.googleapis.com/token
    user-info-uri: https://www.googleapis.com/oauth2/v3/userinfo
    
    

// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/AuthServiceApplication.java
package com.ktds.subs.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/dto/GoogleUserInfo.java
package com.ktds.subs.auth.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class GoogleUserInfo {
    private String id;
    private String email;
    private String name;
    private String picture;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/dto/response/UserProfileResponse.java
package com.ktds.subs.auth.dto.response;

import com.ktds.subs.auth.domain.User;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class UserProfileResponse {
    private String userId;
    private String nickname;
    private String gender;

    public static UserProfileResponse from(User user) {
        return UserProfileResponse.builder()
            .userId(user.getUserId())
            .nickname(user.getNickname())
            .gender(user.getGender())
            .build();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/dto/response/NotificationSettingResponse.java
package com.ktds.subs.auth.dto.response;

import com.ktds.subs.auth.domain.User;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class NotificationSettingResponse {
    private boolean enabled;

    public static NotificationSettingResponse from(User user) {
        return NotificationSettingResponse.builder()
            .enabled(user.isNotificationEnabled())
            .build();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/dto/response/TokenResponse.java
package com.ktds.subs.auth.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class TokenResponse {
    private String accessToken;
    private String refreshToken;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/dto/request/SocialLoginRequest.java
package com.ktds.subs.auth.dto.request;

import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class SocialLoginRequest {
    private String provider;
    private String code;
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/repository/TokenRepository.java
package com.ktds.subs.auth.repository;

import com.ktds.subs.auth.domain.Token;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByRefreshToken(String refreshToken);
    void deleteByUserId(String userId);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/repository/UserRepository.java
package com.ktds.subs.auth.repository;

import com.ktds.subs.auth.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findByProviderAndProviderUserId(String provider, String providerUserId);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/util/JwtTokenProvider.java
package com.ktds.subs.auth.util;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.UUID;

@Component
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.access-token-validity}")
    private long accessTokenValidityInMilliseconds;

    public String createAccessToken(String userId) {
        Claims claims = Jwts.claims().setSubject(userId);
        Date now = new Date();
        Date validity = new Date(now.getTime() + accessTokenValidityInMilliseconds);

        return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(validity)
            .signWith(SignatureAlgorithm.HS256, jwtSecret)
            .compact();
    }

    public String createRefreshToken() {
        return UUID.randomUUID().toString();
    }

    public String getUserId(String token) {
        return Jwts.parser()
            .setSigningKey(jwtSecret)
            .parseClaimsJws(token)
            .getBody()
            .getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/config/SecurityConfig.java
package com.ktds.subs.auth.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authorizeRequests()
            .requestMatchers("/api/auth/**").permitAll()
            .anyRequest().authenticated();
            
        return http.build();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/config/SwaggerConfig.java
package com.ktds.subs.auth.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {
    
    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("인증 서비스 API")
                .description("구독 관리 서비스의 인증 관련 API입니다.")
                .version("1.0"));
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/controller/AuthController.java
package com.ktds.subs.auth.controller;

import com.ktds.subs.auth.dto.request.SocialLoginRequest;
import com.ktds.subs.auth.dto.response.TokenResponse;
import com.ktds.subs.auth.service.AuthService;
import com.ktds.subs.common.dto.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@Tag(name = "인증", description = "인증 관련 API")
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    
    private final AuthService authService;
    
    @Operation(summary = "소셜 로그인", description = "소셜 계정으로 로그인합니다.")
    @PostMapping("/login")
    public ApiResponse<TokenResponse> login(@RequestBody SocialLoginRequest request) {
        return ApiResponse.success(authService.login(request.getProvider(), request.getCode()));
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/controller/UserController.java
package com.ktds.subs.auth.controller;

import com.ktds.subs.auth.service.UserService;
import com.ktds.subs.common.dto.ApiResponse;
import com.ktds.subs.auth.dto.request.UserProfileRequest;
import com.ktds.subs.auth.dto.request.NotificationSettingRequest;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@Tag(name = "사용자", description = "사용자 관련 API")
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @Operation(summary = "프로필 조회", description = "사용자 프로필을 조회합니다.")
    @GetMapping("/{userId}")
    public ApiResponse<?> getProfile(@PathVariable String userId) {
        return ApiResponse.success(userService.getProfile(userId));
    }

    @Operation(summary = "프로필 수정", description = "사용자 프로필을 수정합니다.")
    @PutMapping("/{userId}")
    public ApiResponse<?> updateProfile(
            @PathVariable String userId,
            @RequestBody UserProfileRequest request) {
        return ApiResponse.success(userService.updateProfile(userId, request));
    }

    @Operation(summary = "알림 설정 조회", description = "사용자의 알림 설정을 조회합니다.")
    @GetMapping("/{userId}/notifications")
    public ApiResponse<?> getNotificationSettings(@PathVariable String userId) {
        return ApiResponse.success(userService.getNotificationSettings(userId));
    }

    @Operation(summary = "알림 설정 수정", description = "사용자의 알림 설정을 수정합니다.")
    @PutMapping("/{userId}/notifications")
    public ApiResponse<?> updateNotificationSettings(
            @PathVariable String userId,
            @RequestBody NotificationSettingRequest request) {
        return ApiResponse.success(userService.updateNotificationSettings(userId, request));
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/service/UserService.java
package com.ktds.subs.auth.service;

import com.ktds.subs.auth.dto.request.UserProfileRequest;
import com.ktds.subs.auth.dto.request.NotificationSettingRequest;
import com.ktds.subs.auth.dto.response.UserProfileResponse;
import com.ktds.subs.auth.dto.response.NotificationSettingResponse;

public interface UserService {
    UserProfileResponse getProfile(String userId);
    UserProfileResponse updateProfile(String userId, UserProfileRequest request);
    NotificationSettingResponse getNotificationSettings(String userId);
    NotificationSettingResponse updateNotificationSettings(String userId, NotificationSettingRequest request);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/service/AuthService.java
package com.ktds.subs.auth.service;

import com.ktds.subs.auth.dto.response.TokenResponse;

public interface AuthService {
    TokenResponse login(String provider, String code);
    TokenResponse refresh(String refreshToken);
    void logout(String refreshToken);
    TokenResponse signup(String provider, String code);
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/service/impl/UserServiceImpl.java
package com.ktds.subs.auth.service.impl;

import com.ktds.subs.auth.domain.User;
import com.ktds.subs.auth.dto.request.UserProfileRequest;
import com.ktds.subs.auth.dto.request.NotificationSettingRequest;
import com.ktds.subs.auth.dto.response.UserProfileResponse;
import com.ktds.subs.auth.dto.response.NotificationSettingResponse;
import com.ktds.subs.auth.repository.UserRepository;
import com.ktds.subs.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserProfileResponse getProfile(String userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        return UserProfileResponse.from(user);
    }

    @Override
    @Transactional
    public UserProfileResponse updateProfile(String userId, UserProfileRequest request) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        
        user.setNickname(request.getNickname());
        user.setGender(request.getGender());
        
        return UserProfileResponse.from(userRepository.save(user));
    }

    @Override
    @Transactional(readOnly = true)
    public NotificationSettingResponse getNotificationSettings(String userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        return NotificationSettingResponse.from(user);
    }

    @Override
    @Transactional
    public NotificationSettingResponse updateNotificationSettings(String userId, NotificationSettingRequest request) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        
        user.setNotificationEnabled(request.isEnabled());
        
        return NotificationSettingResponse.from(userRepository.save(user));
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/service/impl/AuthServiceImpl.java
package com.ktds.subs.auth.service.impl;

import com.ktds.subs.auth.domain.Token;
import com.ktds.subs.auth.domain.User;
import com.ktds.subs.auth.dto.response.TokenResponse;
import com.ktds.subs.auth.repository.TokenRepository;
import com.ktds.subs.auth.repository.UserRepository;
import com.ktds.subs.auth.service.AuthService;
import com.ktds.subs.auth.util.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final GoogleOAuthClient googleOAuthClient;

    @Override
    @Transactional
    public TokenResponse login(String provider, String code) {
        // 구글 OAuth로 사용자 정보 조회
        GoogleUserInfo userInfo = googleOAuthClient.getUserInfo(code);
        
        // 기존 사용자 조회 또는 새로운 사용자 생성
        User user = userRepository.findByProviderAndProviderUserId(provider, userInfo.getId())
            .orElseGet(() -> signup(provider, userInfo));

        // 토큰 생성
        String accessToken = jwtTokenProvider.createAccessToken(user.getUserId());
        String refreshToken = jwtTokenProvider.createRefreshToken();

        // Refresh 토큰 저장
        saveRefreshToken(user.getUserId(), refreshToken);

        return new TokenResponse(accessToken, refreshToken);
    }

    @Override
    @Transactional
    public TokenResponse refresh(String refreshToken) {
        // Refresh 토큰 검증
        Token token = tokenRepository.findByRefreshToken(refreshToken)
            .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        // 새로운 액세스 토큰 발급
        String newAccessToken = jwtTokenProvider.createAccessToken(token.getUserId());

        return new TokenResponse(newAccessToken, refreshToken);
    }

    @Override
    @Transactional
    public void logout(String refreshToken) {
        Token token = tokenRepository.findByRefreshToken(refreshToken)
            .orElseThrow(() -> new RuntimeException("Invalid refresh token"));
        tokenRepository.delete(token);
    }

    private User signup(String provider, GoogleUserInfo userInfo) {
        User user = new User();
        user.setUserId(UUID.randomUUID().toString());
        user.setProvider(provider);
        user.setProviderUserId(userInfo.getId());
        user.setNickname(userInfo.getName());
        return userRepository.save(user);
    }

    private void saveRefreshToken(String userId, String refreshToken) {
        Token token = new Token();
        token.setUserId(userId);
        token.setRefreshToken(refreshToken);
        token.setExpiresAt(LocalDateTime.now().plusDays(14));
        tokenRepository.save(token);
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/domain/User.java
package com.ktds.subs.auth.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Getter
@NoArgsConstructor
public class User {
    @Id
    @Column(name = "user_id")
    private String userId;
    
    private String nickname;
    
    private String gender;
    
    private String provider;
    
    @Column(name = "provider_user_id")
    private String providerUserId;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
    
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/domain/Token.java
package com.ktds.subs.auth.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "refresh_tokens")
@Getter
@NoArgsConstructor
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "token_id")
    private Long tokenId;
    
    @Column(name = "user_id")
    private String userId;
    
    @Column(name = "refresh_token")
    private String refreshToken;
    
    @Column(name = "expires_at")
    private LocalDateTime expiresAt;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}


// File: /Users/kth20150064/project/5000.study_project/AX_project/Claude/구독관리서비스/1000.sources/backend/subscription-manager/sub-mgmt/auth-service/src/main/java/com/ktds/subs/auth/client/GoogleOAuthClient.java
package com.ktds.subs.auth.client;

import com.ktds.subs.auth.dto.GoogleUserInfo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class GoogleOAuthClient {

    private final RestTemplate restTemplate;
    
    @Value("${oauth2.google.token-uri}")
    private String tokenUri;
    
    @Value("${oauth2.google.user-info-uri}")
    private String userInfoUri;

    public GoogleOAuthClient() {
        this.restTemplate = new RestTemplate();
    }

    public GoogleUserInfo getUserInfo(String code) {
        // 1. 인증 코드로 액세스 토큰 요청
        String accessToken = getAccessToken(code);
        
        // 2. 액세스 토큰으로 사용자 정보 요청
        return getUserInfoWithToken(accessToken);
    }

    private String getAccessToken(String code) {
        // OAuth 토큰 요청 로직 구현
        return "access_token";
    }

    private GoogleUserInfo getUserInfoWithToken(String accessToken) {
        // 사용자 정보 요청 로직 구현
        return new GoogleUserInfo();
    }
}


