package dev.raul.escape;

import dev.raul.escape.security.JwtConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties(JwtConfig.class)
@SpringBootApplication
public class EscapeApplication {

    static void main(String[] args) {
        SpringApplication.run(EscapeApplication.class, args);
    }

}
