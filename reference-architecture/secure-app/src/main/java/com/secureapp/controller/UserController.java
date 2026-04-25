package com.secureapp.controller;

import com.secureapp.repository.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class UserController {

    private final UserRepository userRepository;

    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Returns the profile of the currently authenticated caller only.
     * No userId path parameter — eliminates IDOR (Insecure Direct Object Reference) vector.
     * JWT validation in JwtAuthenticationFilter guarantees authentication is genuine.
     */
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
        }

        String username = authentication.getName();
        return userRepository.findByUsername(username)
            .map(user -> ResponseEntity.ok(Map.<String, Object>of(
                "username", user.getUsername(),
                "email", user.getEmail()
            )))
            .orElse(ResponseEntity.status(401).build());
    }
}
