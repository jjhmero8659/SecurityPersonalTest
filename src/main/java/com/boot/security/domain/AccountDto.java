package com.boot.security.domain;

import lombok.Data;

import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Data
public class AccountDto {

        private String username;
        private String password;
        private String email;
        private Long age;
        private String role;

}
