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
