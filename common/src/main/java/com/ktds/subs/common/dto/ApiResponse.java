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
