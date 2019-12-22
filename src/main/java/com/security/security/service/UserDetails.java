package com.security.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetails implements UserDetailsService {
    @Autowired
    private UserRepository repository;

    @Autowired
    private RoleRepository roleRepository;

    @Override
    public org.springframework.security.core.userdetails.UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity user = repository.findByUserName(username);

        if (user == null) throw new UsernameNotFoundException("User with username " + username + " not found!");

        RoleEntity admin = roleRepository.findByUsernameAndPassword(user.getUserName(), user.getEncryptedPassword());

        if (admin == null) {
            return User
                    .withUsername(user.getUserName())
                    .password(user.getEncryptedPassword())
                    .roles("USER")
                    .build();
        }

        return User
                .withUsername(user.getUserName())
                .password(user.getEncryptedPassword())
                .roles("ADMIN")
                .build();
    }
}
