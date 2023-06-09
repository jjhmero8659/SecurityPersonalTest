package com.boot.security.domain;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Entity
@Data
public class Account {
    @Id @GeneratedValue
    private Long id;
    private String password;
    private String username;

    private String email;
    private Long age;
    private String role;

}
