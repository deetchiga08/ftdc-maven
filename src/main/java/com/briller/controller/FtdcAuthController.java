package com.briller.controller;

import com.briller.config.AuthenticationTokenService;
import com.briller.model.FtdcUserDetails;
import com.briller.model.Users;
import com.briller.repository.UserRepository;
import com.briller.service.UserService;
import io.swagger.annotations.Api;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@Api("Authentication Service for FTDC Questionaire Application")
@RestController
@RequestMapping("api/services/auth")
public class FtdcAuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService ftdcUserDetailsService;


    @Autowired
    private UserService userService;

    @Autowired
    UserRepository userRepository;

    @Autowired
    private AuthenticationTokenService authenticationTokenService;


    @Value("${briller.jwt.token.header}")
    private String tokenHeader;

    @Async
    @PostMapping(value = "/user/signUp")
    public ResponseEntity<?> signupUser(@RequestBody Users user) throws Exception {
        Map<String, Object> signupResponse = new HashMap<>();
        HttpHeaders headers = new HttpHeaders();
        boolean success = userService.registerUser(user);
        return new ResponseEntity(user, HttpStatus.CREATED);
    }

    @PostMapping(value="/user/login")
    public ResponseEntity<?> login(@RequestBody Users user){
        final Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        user.getUserName(),
                        user.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        final UserDetails userDetails = ftdcUserDetailsService.loadUserByUsername(user.getUserName());
        final String token = authenticationTokenService.generateToken(userDetails);
        FtdcUserDetails loggedinUser = (FtdcUserDetails) authentication.getPrincipal();
        HttpHeaders headers = new HttpHeaders();
        if(token !=null) {
            headers.add(tokenHeader, token);
        }
        return new ResponseEntity<>( loggedinUser,headers, HttpStatus.OK);
    }



}
