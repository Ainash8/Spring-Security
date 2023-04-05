package com.springboot.security.SpringSecurity.service;

import com.springboot.security.SpringSecurity.model.User;

import java.util.Optional;

public interface UserService {
    Integer saveUser(User user);
    Optional<User> findByUsername(String username);
}
