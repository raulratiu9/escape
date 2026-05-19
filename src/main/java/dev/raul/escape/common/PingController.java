package dev.raul.escape.common;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PingController {
    @GetMapping("/api/public/ping")
    public String publicPing() {
        return "public pong";
    }

    @GetMapping("/api/private/ping")
    public String privatePing() {
        return "private pong";
    }

    @GetMapping("/api/admin/ping")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminPing() {
        return "admin pong";
    }
}
