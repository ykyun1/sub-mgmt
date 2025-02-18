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









    
    
    