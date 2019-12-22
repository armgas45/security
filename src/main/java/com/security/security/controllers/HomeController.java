package com.security.security.controllers;

import com.security.security.service.UserDTO;
import com.security.security.service.UserEntity;
import com.security.security.service.UserRepository;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/")
public class HomeController {
    @Autowired
    private UserRepository repository;

    @Autowired
    private BCryptPasswordEncoder encoder;

    @GetMapping
    public String getHomePage() {
        return "<h1>Welcome!</h1> ";
    }

    @PostMapping("/users")
    public boolean addUser(@RequestBody UserDTO userDTO) {
        UserEntity userEntity = new UserEntity();
        BeanUtils.copyProperties(userDTO, userEntity);

        userEntity.setEncryptedPassword(encoder.encode(userDTO.getPassword()));

        return repository.save(userEntity) != null;
    }

    @GetMapping("/admin/a")
    public String getAdminA() {
        return "This is a protected route if you reached here you have to be an admin";
    }

    @GetMapping("/admin")
    public String getAdminPage() {
        return "<h1>Welcome Admin!</h1>";
    }

    @GetMapping("/user")
    public String getUserPage() {
        return "<h1>Welcome User!</h1>";
    }

    @GetMapping("/api/service")
    public String getApi() {
        return "this is a public api";
    }

    @GetMapping("/admin/dash")
    public String adminDash() {
        return "this is admin's dash";
    }

    @GetMapping("/user/dash")
    public String usersDash() {
        return "This is user's dash";
    }
}
