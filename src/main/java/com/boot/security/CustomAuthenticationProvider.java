package com.boot.security;

import com.boot.security.service.AccountContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

@Service
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException { //검증 구현
        System.out.println(authentication);
        String username = authentication.getName();
        System.out.println(username);
        String password = (String) authentication.getCredentials();

        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(username); //DB 조회

        if(!passwordEncoder.matches(password,accountContext.getAccount().getPassword())) {
            throw new BadCredentialsException("BadCredentialsException");
        }

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken
                        (
                                accountContext.getAccount(), // 사용자 정보
                                null, //비밀번호
                                accountContext.getAuthorities() // 사용자 권한
                        );

        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) { //
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
