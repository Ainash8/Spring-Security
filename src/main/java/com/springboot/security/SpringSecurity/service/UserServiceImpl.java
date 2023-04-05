package com.springboot.security.SpringSecurity.service;

import com.springboot.security.SpringSecurity.model.User;
import com.springboot.security.SpringSecurity.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService, UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;
    @Override
    public Integer saveUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getUsername()));
        return userRepository.save(user).getId();

    }

    @Override
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> optUser = findByUsername(username);
        if(optUser.isEmpty())
            throw new UsernameNotFoundException("User not exists");
        User user = optUser.get();

        return new org.springframework.security.core.userdetails.User(
                username,
                user.getPassword(),
                user.getRoles().stream()
                        .map(role->new SimpleGrantedAuthority(role))
                        .collect(Collectors.toList()));
    }
}
