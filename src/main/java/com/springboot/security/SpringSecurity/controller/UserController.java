package com.springboot.security.SpringSecurity.controller;

import com.springboot.security.SpringSecurity.model.User;
import com.springboot.security.SpringSecurity.model.UserRequest;
import com.springboot.security.SpringSecurity.model.UserResponse;
import com.springboot.security.SpringSecurity.service.UserService;
import com.springboot.security.SpringSecurity.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@RequestMapping("/user")
public class UserController {
    @Autowired
    private UserService userService;
    @Autowired
    private JwtUtil util;

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/save")
    public ResponseEntity<String> saveUser(@RequestBody User user){
        Integer id = userService.saveUser(user);
        String body = "User "+id+" saved";
        return  ResponseEntity.ok(body);
    }

    @PostMapping("/login")
    public ResponseEntity<UserResponse> loginUser(@RequestBody UserRequest request){
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(),request.getPassword()));
        String token = util.generateToken(request.getUsername());
        return ResponseEntity.ok(new UserResponse(token,"Success!!! Token generated"));
    }

    @PostMapping("/welcome")
    public ResponseEntity<String> accessData(Principal p){
        return  ResponseEntity.ok(p.getName());
    }

    @GetMapping("/hello")
    public String helloUser(){
        return " Hello User!!!1";
    }
}
