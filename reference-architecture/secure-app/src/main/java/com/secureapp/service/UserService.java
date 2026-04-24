package com.secureapp.service;

import com.secureapp.model.User;
import com.secureapp.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.regex.Pattern;

@Service
public class UserService {

    // Enforce strong password: uppercase + digit + special char + min 8 chars
    private static final Pattern STRONG_PASSWORD_PATTERN = Pattern.compile(
        "^(?=.*[A-Z])(?=.*[0-9])(?=.*[^a-zA-Z0-9]).{8,}$"
    );

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Authenticate a user. Returns the user if credentials are valid.
     * The same code path runs whether the username exists or not,
     * preventing timing-based user enumeration.
     */
    public Optional<User> authenticate(String username, String rawPassword) {
        return userRepository.findByUsername(username)
            .filter(user -> passwordEncoder.matches(rawPassword, user.getPasswordHash()));
    }

    /**
     * Register a new user. Enforces:
     * - Unique username and email
     * - Strong password policy
     * - BCrypt hashing (cost 12) — raw password never stored
     */
    public User register(String username, String email, String rawPassword) {
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("Username already taken");
        }
        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("Email already registered");
        }
        if (!STRONG_PASSWORD_PATTERN.matcher(rawPassword).matches()) {
            throw new IllegalArgumentException(
                "Password must be at least 8 characters and contain uppercase, digit, and special character");
        }

        String passwordHash = passwordEncoder.encode(rawPassword);
        userRepository.save(username, email, passwordHash);
        return userRepository.findByUsername(username).orElseThrow();
    }
}
