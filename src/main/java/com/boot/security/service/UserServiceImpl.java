package com.boot.security.service;

import com.boot.security.domain.Account;
import com.boot.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
@Service("userService")
@RequiredArgsConstructor
public class UserServiceImpl implements UserService{

    private final UserRepository userRepository;
    @Transactional
    @Override
    public void createUser(Account account) {
        userRepository.save(account);
    }
}
