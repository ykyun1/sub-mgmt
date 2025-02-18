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
