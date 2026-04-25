package com.secureapp.controller;

import com.secureapp.dto.AuthResponse;
import com.secureapp.dto.LoginRequest;
import com.secureapp.dto.RegisterRequest;
import com.secureapp.model.User;
import com.secureapp.security.JwtUtil;
import com.secureapp.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Optional;

@RestController
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;

    public AuthController(UserService userService, JwtUtil jwtUtil) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        Optional<User> user = userService.authenticate(request.getUsername(), request.getPassword());

        if (user.isEmpty()) {
            // Generic error — does not reveal whether username exists or password is wrong
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Credenciales inválidas"));
        }

        String token = jwtUtil.generateToken(user.get().getUsername(), user.get().getId());
        return ResponseEntity.ok(new AuthResponse(token, 3600L));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        try {
            User created = userService.register(
                request.getUsername(), request.getEmail(), request.getPassword());
            return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of(
                    "message", "User registered successfully",
                    "username", created.getUsername()
                ));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(Map.of("error", e.getMessage()));
        }
    }
}
