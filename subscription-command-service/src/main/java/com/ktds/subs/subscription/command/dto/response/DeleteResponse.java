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
