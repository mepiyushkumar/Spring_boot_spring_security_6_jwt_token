package com.example.spring_security_jwt.service;

import com.example.spring_security_jwt.entity.User;
import com.example.spring_security_jwt.entity.UserDetailsPrinciple;
import com.example.spring_security_jwt.repo.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepo userRepo;



    @Override
    public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {

        User user = userRepo.findByUserId(userId);

        if(user  == null){
            System.out.println("User not found");
            throw new UsernameNotFoundException("user not Found!!");
        }
        return new UserDetailsPrinciple(user);

    }
}
