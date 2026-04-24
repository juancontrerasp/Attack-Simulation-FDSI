package com.secureapp.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

public class RateLimitFilter extends OncePerRequestFilter {

    private static final int MAX_REQUESTS_PER_MINUTE = 5;
    private final ConcurrentHashMap<String, Bucket> loginBuckets = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if ("/login".equals(request.getServletPath())) {
            String clientIp = extractClientIp(request);
            Bucket bucket = loginBuckets.computeIfAbsent(clientIp, ip -> createLoginBucket());

            if (!bucket.tryConsume(1)) {
                long resetEpoch = (System.currentTimeMillis() / 1000L) + 60L;
                response.setHeader("X-RateLimit-Limit", String.valueOf(MAX_REQUESTS_PER_MINUTE));
                response.setHeader("X-RateLimit-Remaining", "0");
                response.setHeader("X-RateLimit-Reset", String.valueOf(resetEpoch));
                response.setHeader("Retry-After", "60");
                response.setStatus(429);
                response.setContentType("application/json;charset=UTF-8");
                response.getWriter().write("{\"error\":\"Too many login attempts. Please try again later.\"}");
                return;
            }

            long remaining = bucket.getAvailableTokens();
            long resetEpoch = (System.currentTimeMillis() / 1000L) + 60L;
            response.setHeader("X-RateLimit-Limit", String.valueOf(MAX_REQUESTS_PER_MINUTE));
            response.setHeader("X-RateLimit-Remaining", String.valueOf(remaining));
            response.setHeader("X-RateLimit-Reset", String.valueOf(resetEpoch));
        }

        filterChain.doFilter(request, response);
    }

    private Bucket createLoginBucket() {
        Bandwidth limit = Bandwidth.classic(
            MAX_REQUESTS_PER_MINUTE,
            Refill.intervally(MAX_REQUESTS_PER_MINUTE, Duration.ofMinutes(1))
        );
        return Bucket.builder().addLimit(limit).build();
    }

    private String extractClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            // Take only the first (leftmost) IP to prevent spoofing via header injection
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
