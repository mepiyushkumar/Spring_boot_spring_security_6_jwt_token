package com.example.spring_security_jwt.service;


import com.example.spring_security_jwt.entity.User;
import com.example.spring_security_jwt.repo.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class UserService {
    @Autowired
    UserRepo userRepo;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    JwtService jwtService;


    public User createUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepo.save(user);
        return user;
    }

    public String verify(User user) throws Exception {
        try {
            Authentication authentication = authenticationManager.
                    // This authenticates the user's credentials (userId and password). If valid, proceeds to generate a token.

                            //DaoAuthenticationProvider  is called here
                            authenticate(new UsernamePasswordAuthenticationToken(user.getUserId(), user.getPassword()));

            if (authentication.isAuthenticated()) {
                return "Valid user. Token : " + jwtService.generateToken(user);

            }
            return "Invalid user - User not Authenticated";


        }catch (Exception e){
            return "Invalid user - Authentication failed: " + e.getMessage();
        }
    }
}
