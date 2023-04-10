package com.boot.security.controller;

import com.boot.security.CustomAuthenticationProvider;
import com.boot.security.domain.Account;
import com.boot.security.domain.AccountDto;
import com.boot.security.service.UserService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
@CrossOrigin("*")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    private final CustomAuthenticationProvider customAuthenticationProvider;

    @PutMapping("/sign/up")
    public Integer SignUp(@RequestBody AccountDto accountDto) {
        ModelMapper modelMapper = new ModelMapper();
        Account account = modelMapper.map(accountDto, Account.class);
        account.setPassword(passwordEncoder.encode(account.getPassword()));
        userService.createUser(account);
        return 1;
    }


//    @PostMapping("/sign/login")
//    public ResponseEntity<String> login(@RequestParam("id") String id, @RequestParam("password") String password) {
//        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(id, password);
//        try {
//            Authentication authentication = authenticationManager.authenticate(token);
//            SecurityContextHolder.getContext().setAuthentication(authentication);
//            return ResponseEntity.ok("로그인 성공");
//        } catch (AuthenticationException e) {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("로그인 실패");
//        }
//    }

    @GetMapping("/sign/login")
    public ResponseEntity<String> login(@RequestParam("id") String id, @RequestParam("password") String password) {
        System.out.println(id +" ////////////////"+ password);
        Authentication token = new UsernamePasswordAuthenticationToken(id, password);
        try {
            Authentication authentication = customAuthenticationProvider.authenticate(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            System.out.println("로그인 성공");
            return ResponseEntity.ok("로그인 성공");
        } catch (AuthenticationException e) {
            System.out.println("로그인 실패");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("로그인 실패");
        }
    }



    @GetMapping("/sign/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if(authentication != null){
            new SecurityContextLogoutHandler().logout(request,response,authentication);
        }

        return "로그아웃";
    }
}
