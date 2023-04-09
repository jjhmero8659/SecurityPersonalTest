package com.boot.security.domain;

import lombok.Data;

import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Data
public class AccountDto {

        private String userName;
        private String passWord;
        private String email;
        private Long age;
        private String role;

}
