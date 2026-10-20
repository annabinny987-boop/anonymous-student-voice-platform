package com.asvp.studentvoice.controller;

import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/emergency")
public class EmergencyController {

    private final JdbcTemplate jdbc;

    public EmergencyController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /*
     * STUDENTS:
     * Anyone can submit an emergency alert.
     * Viewing and managing alerts requires administrator access.
     */

    @PostMapping
    public Map<String, Object> submitAlert(
            @RequestBody EmergencyRequest request) {

        if (request.alertType() == null
                || request.alertType().isBlank()
                || request.details() == null
                || request.details().isBlank()) {

            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Emergency type and details are required."
            );
        }

        String alertType = request.alertType().trim();
        String details = request.details().trim();

        if (alertType.length() > 100) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Emergency type must not exceed 100 characters."
            );
        }

        if (details.length() > 10000) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Emergency details must not exceed 10000 characters."
            );
        }

        jdbc.update("""
                INSERT INTO emergency_alerts
                    (alert_type, details, status)
                VALUES (?, ?, ?)
                """,
                alertType,
                details,
                "NEW"
        );

        return Map.of(
                "message", "Emergency alert submitted successfully.",
                "status", "NEW"
        );
    }

    /*
     * ADMIN ONLY:
     * Retrieve emergency alerts.
     */

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public List<Map<String, Object>> getAlerts() {

        return jdbc.queryForList("""
                SELECT id, alert_type, details, status, created_at
                FROM emergency_alerts
                ORDER BY created_at DESC
                """);
    }

    /*
     * ADMIN ONLY:
     * Update the status of an emergency alert.
     */

    @PutMapping("/{id}/status")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, String> updateAlertStatus(
            @PathVariable long id,
            @RequestBody StatusRequest request) {

        if (id <= 0) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Invalid emergency alert ID."
            );
        }

        if (request.status() == null
                || !List.of(
                        "NEW",
                        "ACKNOWLEDGED",
                        "RESOLVED"
                ).contains(request.status())) {

            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Status must be NEW, ACKNOWLEDGED, or RESOLVED."
            );
        }

        int updated = jdbc.update("""
                UPDATE emergency_alerts
                SET status = ?
                WHERE id = ?
                """,
                request.status(),
                id
        );

        if (updated == 0) {
            throw new ResponseStatusException(
                    HttpStatus.NOT_FOUND,
                    "Emergency alert not found."
            );
        }

        return Map.of(
                "message", "Emergency alert status updated successfully.",
                "status", request.status()
        );
    }

    public record EmergencyRequest(
            String alertType,
            String details
    ) {}

    public record StatusRequest(
            String status
    ) {}
}