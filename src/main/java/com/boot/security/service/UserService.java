package com.boot.security.service;

import com.boot.security.domain.Account;
import com.boot.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

public interface UserService{

    public void createUser(Account account);
}
