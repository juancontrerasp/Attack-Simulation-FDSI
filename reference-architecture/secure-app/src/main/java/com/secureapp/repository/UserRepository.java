package com.secureapp.repository;

import com.secureapp.model.User;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public class UserRepository {

    private final JdbcTemplate jdbcTemplate;

    public UserRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    private static final RowMapper<User> USER_MAPPER = (rs, rowNum) -> new User(
        rs.getLong("id"),
        rs.getString("username"),
        rs.getString("email"),
        rs.getString("password_hash")
    );

    // Parameterized query — username is a bound parameter, not concatenated
    public Optional<User> findByUsername(String username) {
        String sql = "SELECT id, username, email, password_hash FROM users WHERE username = ?";
        List<User> results = jdbcTemplate.query(sql, USER_MAPPER, username);
        return results.stream().findFirst();
    }

    // Parameterized query — email is a bound parameter
    public boolean existsByEmail(String email) {
        String sql = "SELECT COUNT(*) FROM users WHERE email = ?";
        Integer count = jdbcTemplate.queryForObject(sql, Integer.class, email);
        return count != null && count > 0;
    }

    // Parameterized query — username is a bound parameter
    public boolean existsByUsername(String username) {
        String sql = "SELECT COUNT(*) FROM users WHERE username = ?";
        Integer count = jdbcTemplate.queryForObject(sql, Integer.class, username);
        return count != null && count > 0;
    }

    // Parameterized insert — all three values are bound parameters
    public void save(String username, String email, String passwordHash) {
        String sql = "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)";
        jdbcTemplate.update(sql, username, email, passwordHash);
    }
}
