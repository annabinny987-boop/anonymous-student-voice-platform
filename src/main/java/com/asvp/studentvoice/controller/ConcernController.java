
package com.asvp.studentvoice.controller;

import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/concerns")
public class ConcernController {

    private final JdbcTemplate jdbc;

    public ConcernController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // STUDENT: Submit an anonymous concern.
    @PostMapping
    public Map<String, String> submitConcern(
            @RequestBody ConcernRequest request) {

        if (request.category() == null || request.category().isBlank()
                || request.message() == null || request.message().isBlank()) {

            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Category and concern description are required."
            );
        }

        String category = request.category().trim();
        String message = request.message().trim();

        if (category.length() > 100 || message.length() > 10000) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Category or concern description is too long."
            );
        }

        String trackingCode = "ASVP-" +
                java.util.UUID.randomUUID()
                        .toString()
                        .substring(0, 8)
                        .toUpperCase();

        jdbc.update("""
                INSERT INTO concerns
                    (tracking_code, category, message, status)
                VALUES (?, ?, ?, ?)
                """,
                trackingCode,
                category,
                message,
                "Pending"
        );

        return Map.of(
                "message", "Concern submitted successfully.",
                "trackingCode", trackingCode
        );
    }

    // STUDENT: Track an individual concern using its tracking code.
    @GetMapping("/{trackingCode}")
    public Map<String, Object> trackConcern(
            @PathVariable String trackingCode) {

        var results = jdbc.queryForList("""
                SELECT tracking_code, category, status, admin_reply, created_at
                FROM concerns
                WHERE tracking_code = ?
                """,
                trackingCode.trim().toUpperCase()
        );

        if (results.isEmpty()) {
            throw new ResponseStatusException(
                    HttpStatus.NOT_FOUND,
                    "No concern found for this tracking code."
            );
        }

        return results.get(0);
    }

    // ADMIN ONLY: Retrieve all concerns for the dashboard.
    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public List<Map<String, Object>> getAllConcerns() {

        return jdbc.queryForList("""
                SELECT tracking_code, category, message, status,
                       admin_reply, created_at
                FROM concerns
                ORDER BY created_at DESC
                """);
    }

    // ADMIN ONLY: Save a detailed reply and update the concern status.
    @PutMapping("/{trackingCode}/reply")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, String> replyToConcern(
            @PathVariable String trackingCode,
            @RequestBody ReplyRequest request) {

        if (request.reply() == null || request.reply().isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Please enter a reply before saving."
            );
        }

        if (request.reply().trim().length() > 5000) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Reply cannot exceed 5000 characters."
            );
        }

        if (request.status() == null ||
                !List.of("Pending", "In Progress", "Resolved")
                        .contains(request.status())) {

            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Invalid concern status."
            );
        }

        String code = trackingCode.trim().toUpperCase();

        int updated = jdbc.update("""
                UPDATE concerns
                SET admin_reply = ?, status = ?
                WHERE tracking_code = ?
                """,
                request.reply().trim(),
                request.status(),
                code
        );

        if (updated == 0) {
            throw new ResponseStatusException(
                    HttpStatus.NOT_FOUND,
                    "Concern not found."
            );
        }

        return Map.of(
                "message", "Reply saved successfully.",
                "trackingCode", code,
                "status", request.status()
        );
    }

    public record ConcernRequest(String category, String message) {}

    public record ReplyRequest(String reply, String status) {}
}