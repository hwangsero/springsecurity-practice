package com.cos.securityex01.config.jwt;

import lombok.Data;

@Data
public class UsernameAndPasswordAuthenticationRequest {

    private String username;
    private String password;
}
