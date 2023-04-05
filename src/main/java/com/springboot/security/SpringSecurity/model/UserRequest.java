package com.springboot.security.SpringSecurity.model;

import lombok.Data;

@Data
public class UserRequest {

    private String username;
    private String password;
}
