package com.example.spring_security_jwt.controller;


import com.example.spring_security_jwt.entity.User;
import com.example.spring_security_jwt.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

@RestController
public class Controller {

    @GetMapping("/home")
    public String home(HttpServletRequest request) {
        return "Home " + request.getSession().getId();
    }

    @GetMapping("/csrf")
    public CsrfToken csrf(HttpServletRequest request) {
        return (CsrfToken) request.getAttribute("_csrf");
    }

    @Autowired
    UserService userService;

    @PostMapping("/create")
    public User create(@RequestBody User user) {

        return userService.createUser(user);
    }

    @GetMapping("/login")
    public String login(@RequestBody User user) {
        try {

        return userService.verify(user);
        }catch (Exception e){
            return e.getMessage();
        }

    }


}
