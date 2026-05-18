package dev.raul.escape.common;

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
}
