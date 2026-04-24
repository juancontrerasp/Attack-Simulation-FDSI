package com.secureapp.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class SecurityHeadersFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // Prevent clickjacking
        response.setHeader("X-Frame-Options", "DENY");

        // Prevent MIME-type sniffing
        response.setHeader("X-Content-Type-Options", "nosniff");

        // Force HTTPS for 1 year; include subdomains; eligible for preload list
        response.setHeader("Strict-Transport-Security",
            "max-age=31536000; includeSubDomains; preload");

        // Restrict content sources; block inline scripts; disable object embeds
        response.setHeader("Content-Security-Policy",
            "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'");

        // Prevent referrer header from leaking sensitive URL fragments
        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

        // No caching of authenticated API responses
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
        response.setHeader("Pragma", "no-cache");

        // Remove server version disclosure
        response.setHeader("X-Powered-By", "");

        filterChain.doFilter(request, response);
    }
}
