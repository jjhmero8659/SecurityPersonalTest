package com.boot.security.controller;

import com.boot.security.domain.Account;
import com.boot.security.domain.AccountDto;
import com.boot.security.service.UserService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin("*")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    @PutMapping("/sign/up")
    public void addReviewInquiry(AccountDto accountDto) {
        System.out.println("accountDto.toString() : "+accountDto.toString());
        ModelMapper modelMapper = new ModelMapper();
        Account account = modelMapper.map(accountDto, Account.class);
        account.setPassWord(passwordEncoder.encode(account.getPassWord()));
        userService.createUser(account);

    }
}
